// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020- OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "crypto_aead.h"
#include "crypto.h"
#include "pktid.h"
#include "proto.h"
#include "skb.h"

#include <crypto/aead.h>
#include <linux/skbuff.h>
#include <linux/printk.h>

void ovpn_decrypt_async_cb(struct crypto_async_request *areq, int ret);
void ovpn_encrypt_async_cb(struct crypto_async_request *areq, int ret);

/* like aead_request_alloc, but allocates extra space for scatterlist[nfrags + 2] */
static __always_inline struct aead_request *
ovpn_aead_request_alloc(struct crypto_aead *tfm, int nfrags, gfp_t gfp)
{
	struct aead_request *req;

	req = kmalloc(ALIGN(sizeof(*req) + crypto_aead_reqsize(tfm), __alignof__(struct scatterlist)) +
		      sizeof(struct scatterlist) * (nfrags + 2), gfp);

	if (likely(req))
		aead_request_set_tfm(req, tfm);

	return req;
}

static struct scatterlist *ovpn_aead_request_to_sg(struct aead_request *req, struct crypto_aead *tfm)
{
	return (void *)req + ALIGN(sizeof(*req) + crypto_aead_reqsize(tfm), __alignof__(struct scatterlist));
}

int ovpn_aead_encrypt(struct ovpn_crypto_key_slot *ks, struct sk_buff *skb, u32 peer_id)
{
	struct scatterlist *sg = NULL, *dsg;
	struct aead_request *req;
	struct sk_buff *nskb, *frag_skb;
	u8 iv[NONCE_SIZE];
	int nfrags, ret;
	u32 pktid, op;

	/* Sample AEAD header format:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 */

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_shinfo(skb)->nr_frags + 1;
	skb_walk_frags(skb, frag_skb)
		nfrags += skb_shinfo(frag_skb)->nr_frags + 1;

	if (unlikely(nfrags > MAX_SKB_FRAGS))
		return -ENOSPC;

	req = ovpn_aead_request_alloc(ks->encrypt, nfrags, GFP_KERNEL);
	if (unlikely(!req))
		return -ENOMEM;

	sg = ovpn_aead_request_to_sg(req, ks->encrypt);
	/* sg table:
	 * 0: op, wire nonce (AD, len=OVPN_OP_SIZE_V2+NONCE_WIRE_SIZE),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 1);

	/* build scatterlist to encrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, 0, skb->len);
	if (unlikely(nfrags != ret)) {
		ret = -EINVAL;
		goto free_req;
	}

	/* obtain packet ID, which is used both as a first
	 * 4 bytes of nonce and last 4 bytes of associated data.
	 */
	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret < 0))
		goto free_req;

	nskb = __alloc_skb(skb->len + NET_IP_ALIGN + NET_SKB_PAD + 32, GFP_KERNEL, 0, NUMA_NO_NODE);
	if (unlikely(!nskb)) {
		ret = -ENOMEM;
		goto free_req;
	}

	skb_reserve(nskb, NET_IP_ALIGN + NET_SKB_PAD);
	dsg = (struct scatterlist *)nskb->cb;
	sg_init_table(dsg, 2);
	sg_set_buf(dsg + 1, __skb_put(nskb, skb->len), SKB_DATA_ALIGN(skb->len + AUTH_TAG_SIZE));
	sg_set_buf(dsg, __skb_push(nskb, AUTH_TAG_SIZE + NONCE_WIRE_SIZE + OVPN_OP_SIZE_V2), NONCE_WIRE_SIZE + OVPN_OP_SIZE_V2);
	OVPN_ASYNC_SKB_CB(skb)->nskb = nskb;

	/* concat 4 bytes packet id and 8 bytes nonce tail into 12 bytes nonce */
	ovpn_pktid_aead_write(pktid, &ks->nonce_tail_xmit, iv);

	/* make space for packet id and push it to the front */
	memcpy(nskb->data + OVPN_OP_SIZE_V2, iv, NONCE_WIRE_SIZE);

	/* add packet op as head of additional data */
	op = ovpn_opcode_compose(OVPN_DATA_V2, ks->key_id, peer_id);
	BUILD_BUG_ON(sizeof(op) != OVPN_OP_SIZE_V2);
	*((__force __be32 *)nskb->data) = htonl(op);

	/* AEAD Additional data */
	sg_set_buf(sg, nskb->data, OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				       CRYPTO_TFM_REQ_MAY_SLEEP,
				  ovpn_encrypt_async_cb, skb);
	aead_request_set_crypt(req, sg, dsg, skb->len, iv);
	aead_request_set_ad(req, OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE);

	/* encrypt it */
	ret = crypto_aead_encrypt(req);
	if (ret == -EINPROGRESS) {
		return ret;
	}
	if (ret < 0) {
		net_err_ratelimited("%s: encrypt failed: %d\n", __func__, ret);
		kfree_skb(nskb);
	}
free_req:
	aead_request_free(req);
	return ret;
}

int ovpn_aead_decrypt(struct ovpn_crypto_key_slot *ks, struct sk_buff *skb)
{
	const unsigned int tag_size = AUTH_TAG_SIZE;
	struct sk_buff *nskb = NULL, *frag_skb;
	struct scatterlist *sg = NULL, *dsg = NULL;
	int ret, payload_len, nfrags;
	u8 *sg_data, iv[NONCE_SIZE];
	unsigned int payload_offset;
	struct aead_request *req;
	unsigned int sg_len;
	__be32 *pid;

	payload_offset = OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE + tag_size;
	payload_len = skb->len - payload_offset;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0))
		return -EINVAL;

	/* Prepare the skb data buffer to be accessed up until the auth tag.
	 * This is required because this area is directly mapped into the sg list.
	 */
	if (unlikely(!pskb_may_pull(skb, payload_offset)))
		return -ENODATA;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_shinfo(skb)->nr_frags + 1;
	skb_walk_frags(skb, frag_skb)
		nfrags += skb_shinfo(frag_skb)->nr_frags + 1;

	if (unlikely(nfrags > MAX_SKB_FRAGS))
		return -ENOSPC;

	req = ovpn_aead_request_alloc(ks->decrypt, nfrags, GFP_KERNEL);
	if (unlikely(!req))
		return -ENOMEM;

	sg = ovpn_aead_request_to_sg(req, ks->decrypt);
	/* sg table:
	 * 0: op, wire nonce (AD, len=OVPN_OP_SIZE_V2+NONCE_WIRE_SIZE),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* packet op is head of additional data */
	sg_data = skb->data;
	sg_len = OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE;
	sg_set_buf(sg, sg_data, sg_len);

	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, payload_offset, payload_len);
	if (unlikely(nfrags != ret)) {
		ret = -EINVAL;
		goto free_req;
	}

	nskb = __alloc_skb(payload_len + NET_IP_ALIGN + NET_SKB_PAD + 32, GFP_KERNEL, 0, NUMA_NO_NODE);
	if ((unlikely(!nskb))) {
		ret = -ENOMEM;
		goto free_req;
	}

	skb_reserve(nskb, NET_IP_ALIGN + NET_SKB_PAD);
	dsg = (struct scatterlist *)nskb->cb;
	sg_init_table(dsg, 2);
	sg_set_buf(dsg, skb->data, NONCE_WIRE_SIZE + OVPN_OP_SIZE_V2);
	sg_set_buf(dsg + 1, __skb_put(nskb, payload_len), SKB_DATA_ALIGN(payload_len));
	OVPN_ASYNC_SKB_CB(skb)->nskb = nskb;

	/* append auth_tag onto scatterlist */
	sg_set_buf(sg + nfrags + 1, skb->data + sg_len, tag_size);

	/* copy nonce into IV buffer */
	memcpy(iv, skb->data + OVPN_OP_SIZE_V2, NONCE_WIRE_SIZE);
	memcpy(iv + NONCE_WIRE_SIZE, ks->nonce_tail_recv.u8,
	       sizeof(struct ovpn_nonce_tail));

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->decrypt);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				       CRYPTO_TFM_REQ_MAY_SLEEP,
				  ovpn_decrypt_async_cb, skb);
	aead_request_set_crypt(req, sg, dsg, payload_len + tag_size, iv);

	aead_request_set_ad(req, NONCE_WIRE_SIZE + OVPN_OP_SIZE_V2);

	/* decrypt it */
	ret = crypto_aead_decrypt(req);
	if (ret == -EINPROGRESS) {
		return ret;
	}
	if (ret < 0) {
		net_err_ratelimited("%s: decrypt failed: %d\n", __func__, ret);
		kfree_skb(nskb);
		goto free_req;
	}

	/* PID sits after the op */
	pid = (__force __be32 *)(skb->data + OVPN_OP_SIZE_V2);
	ret = ovpn_pktid_recv(&ks->pid_recv, ntohl(*pid), 0);
	if (unlikely(ret < 0))
		goto free_req;

free_req:
	aead_request_free(req);
	return ret;
}

/* Initialize a struct crypto_aead object */
struct crypto_aead *ovpn_aead_init(const char *title, const char *alg_name,
				   const unsigned char *key, unsigned int keylen)
{
	struct crypto_aead *aead;
	int ret;

	aead = crypto_alloc_aead(alg_name, 0, 0);
	if (IS_ERR(aead)) {
		ret = PTR_ERR(aead);
		pr_err("%s crypto_alloc_aead failed, err=%d\n", title, ret);
		aead = NULL;
		goto error;
	}

	ret = crypto_aead_setkey(aead, key, keylen);
	if (ret) {
		pr_err("%s crypto_aead_setkey size=%u failed, err=%d\n", title, keylen, ret);
		goto error;
	}

	ret = crypto_aead_setauthsize(aead, AUTH_TAG_SIZE);
	if (ret) {
		pr_err("%s crypto_aead_setauthsize failed, err=%d\n", title, ret);
		goto error;
	}

	/* basic AEAD assumption */
	if (crypto_aead_ivsize(aead) != NONCE_SIZE) {
		pr_err("%s IV size must be %d\n", title, NONCE_SIZE);
		ret = -EINVAL;
		goto error;
	}

	pr_debug("********* Cipher %s (%s)\n", alg_name, title);
	pr_debug("*** IV size=%u\n", crypto_aead_ivsize(aead));
	pr_debug("*** req size=%u\n", crypto_aead_reqsize(aead));
	pr_debug("*** block size=%u\n", crypto_aead_blocksize(aead));
	pr_debug("*** auth size=%u\n", crypto_aead_authsize(aead));
	pr_debug("*** alignmask=0x%x\n", crypto_aead_alignmask(aead));

	return aead;

error:
	crypto_free_aead(aead);
	return ERR_PTR(ret);
}

void ovpn_aead_crypto_key_slot_destroy(struct ovpn_crypto_key_slot *ks)
{
	if (!ks)
		return;

	crypto_free_aead(ks->encrypt);
	crypto_free_aead(ks->decrypt);
	kfree(ks);
}

static struct ovpn_crypto_key_slot *
ovpn_aead_crypto_key_slot_init(enum ovpn_cipher_alg alg,
			       const unsigned char *encrypt_key,
			       unsigned int encrypt_keylen,
			       const unsigned char *decrypt_key,
			       unsigned int decrypt_keylen,
			       const unsigned char *encrypt_nonce_tail,
			       unsigned int encrypt_nonce_tail_len,
			       const unsigned char *decrypt_nonce_tail,
			       unsigned int decrypt_nonce_tail_len,
			       u16 key_id)
{
	struct ovpn_crypto_key_slot *ks = NULL;
	const char *alg_name;
	int ret;

	/* validate crypto alg */
	switch (alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		alg_name = "gcm(aes)";
		break;
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
		alg_name = "rfc7539(chacha20,poly1305)";
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	/* build the key slot */
	ks = kmalloc(sizeof(*ks), GFP_KERNEL);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	ks->encrypt = NULL;
	ks->decrypt = NULL;
	kref_init(&ks->refcount);
	ks->key_id = key_id;

	ks->encrypt = ovpn_aead_init("encrypt", alg_name, encrypt_key,
				     encrypt_keylen);
	if (IS_ERR(ks->encrypt)) {
		ret = PTR_ERR(ks->encrypt);
		ks->encrypt = NULL;
		goto destroy_ks;
	}

	ks->decrypt = ovpn_aead_init("decrypt", alg_name, decrypt_key,
				     decrypt_keylen);
	if (IS_ERR(ks->decrypt)) {
		ret = PTR_ERR(ks->decrypt);
		ks->decrypt = NULL;
		goto destroy_ks;
	}

	if (sizeof(struct ovpn_nonce_tail) != encrypt_nonce_tail_len ||
	    sizeof(struct ovpn_nonce_tail) != decrypt_nonce_tail_len) {
		ret = -EINVAL;
		goto destroy_ks;
	}

	memcpy(ks->nonce_tail_xmit.u8, encrypt_nonce_tail,
	       sizeof(struct ovpn_nonce_tail));
	memcpy(ks->nonce_tail_recv.u8, decrypt_nonce_tail,
	       sizeof(struct ovpn_nonce_tail));

	/* init packet ID generation/validation */
	ovpn_pktid_xmit_init(&ks->pid_xmit);
	ovpn_pktid_recv_init(&ks->pid_recv);

	return ks;

destroy_ks:
	ovpn_aead_crypto_key_slot_destroy(ks);
	return ERR_PTR(ret);
}

struct ovpn_crypto_key_slot *
ovpn_aead_crypto_key_slot_new(const struct ovpn_key_config *kc)
{
	return ovpn_aead_crypto_key_slot_init(kc->cipher_alg,
					      kc->encrypt.cipher_key,
					      kc->encrypt.cipher_key_size,
					      kc->decrypt.cipher_key,
					      kc->decrypt.cipher_key_size,
					      kc->encrypt.nonce_tail,
					      kc->encrypt.nonce_tail_size,
					      kc->decrypt.nonce_tail,
					      kc->decrypt.nonce_tail_size,
					      kc->key_id);
}
