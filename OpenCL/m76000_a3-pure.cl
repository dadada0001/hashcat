/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct cryptojs
{
  u32 first_blocks[32]; // first N ciphertext blocks (up to 8 * 16 = 128 bytes)
  int first_blocks_cnt; // number of 16-byte blocks stored
  u32 last_iv[4];       // second-to-last ciphertext block (CBC IV for last block)
  u32 last_enc[4];      // last ciphertext block
  int data_len;         // total ciphertext length

} cryptojs_t;

KERNEL_FQ KERNEL_FA void m76000_mxx (KERN_ATTR_VECTOR_ESALT (cryptojs_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
  };

  /**
   * base
   */

  u32 s[2];

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const int data_len = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;

  u32 enc[4];

  enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].last_enc[0];
  enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].last_enc[1];
  enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].last_enc[2];
  enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].last_enc[3];

  u32 last_iv[4];

  last_iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].last_iv[0];
  last_iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].last_iv[1];
  last_iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].last_iv[2];
  last_iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].last_iv[3];

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[32] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    md5_ctx_t ctx;

    // D1 = MD5(password || salt)

    md5_init (&ctx);

    md5_update (&ctx, w, pw_len);

    u32 t[16];

    t[ 0] = s[0];
    t[ 1] = s[1];
    t[ 2] = 0;
    t[ 3] = 0;
    t[ 4] = 0;
    t[ 5] = 0;
    t[ 6] = 0;
    t[ 7] = 0;
    t[ 8] = 0;
    t[ 9] = 0;
    t[10] = 0;
    t[11] = 0;
    t[12] = 0;
    t[13] = 0;
    t[14] = 0;
    t[15] = 0;

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    u32 ukey[8];

    ukey[0] = ctx.h[0];
    ukey[1] = ctx.h[1];
    ukey[2] = ctx.h[2];
    ukey[3] = ctx.h[3];

    // D2 = MD5(D1 || password || salt)

    md5_init (&ctx);

    ctx.w0[0] = ukey[0];
    ctx.w0[1] = ukey[1];
    ctx.w0[2] = ukey[2];
    ctx.w0[3] = ukey[3];

    ctx.len = 16;

    md5_update (&ctx, w, pw_len);

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    ukey[4] = ctx.h[0];
    ukey[5] = ctx.h[1];
    ukey[6] = ctx.h[2];
    ukey[7] = ctx.h[3];

    // D3 = MD5(D2 || password || salt)

    u32 d2[4];

    d2[0] = ctx.h[0];
    d2[1] = ctx.h[1];
    d2[2] = ctx.h[2];
    d2[3] = ctx.h[3];

    md5_init (&ctx);

    ctx.w0[0] = d2[0];
    ctx.w0[1] = d2[1];
    ctx.w0[2] = d2[2];
    ctx.w0[3] = d2[3];

    ctx.len = 16;

    md5_update (&ctx, w, pw_len);

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    // D3 = derived IV (keep LE, no swap)

    u32 d3[4];

    d3[0] = ctx.h[0];
    d3[1] = ctx.h[1];
    d3[2] = ctx.h[2];
    d3[3] = ctx.h[3];

    // AES-256

    ukey[0] = hc_swap32_S (ukey[0]);
    ukey[1] = hc_swap32_S (ukey[1]);
    ukey[2] = hc_swap32_S (ukey[2]);
    ukey[3] = hc_swap32_S (ukey[3]);
    ukey[4] = hc_swap32_S (ukey[4]);
    ukey[5] = hc_swap32_S (ukey[5]);
    ukey[6] = hc_swap32_S (ukey[6]);
    ukey[7] = hc_swap32_S (ukey[7]);

    u32 ks[60];

    AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 dec[4];

    aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    // CBC XOR with IV

    u32 iv[4];

    if (data_len == 16)
    {
      iv[0] = d3[0];
      iv[1] = d3[1];
      iv[2] = d3[2];
      iv[3] = d3[3];
    }
    else
    {
      iv[0] = last_iv[0];
      iv[1] = last_iv[1];
      iv[2] = last_iv[2];
      iv[3] = last_iv[3];
    }

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int paddingv = pkcs_padding_bs16 (dec, 16);

    if (paddingv == -1) continue;

    // verify decrypted content is printable ASCII

    if (data_len > 16)
    {
      // multi-block: decrypt and check up to first_blocks_cnt blocks

      const int blocks_cnt = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks_cnt;

      int block_valid = 1;

      for (int b = 0; b < blocks_cnt; b++)
      {
        const int off = b * 4;

        u32 ct[4];

        ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[off + 0];
        ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[off + 1];
        ct[2] = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[off + 2];
        ct[3] = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[off + 3];

        u32 pt[4];

        aes256_decrypt (ks, ct, pt, s_td0, s_td1, s_td2, s_td3, s_td4);

        // CBC XOR: first block uses derived IV, rest use previous ciphertext block

        if (b == 0)
        {
          pt[0] ^= d3[0];
          pt[1] ^= d3[1];
          pt[2] ^= d3[2];
          pt[3] ^= d3[3];
        }
        else
        {
          const int prev = (b - 1) * 4;

          pt[0] ^= esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[prev + 0];
          pt[1] ^= esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[prev + 1];
          pt[2] ^= esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[prev + 2];
          pt[3] ^= esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[prev + 3];
        }

        if (is_valid_printable_32_incl_common_control (pt[0]) == 0) { block_valid = 0; break; }
        if (is_valid_printable_32_incl_common_control (pt[1]) == 0) { block_valid = 0; break; }
        if (is_valid_printable_32_incl_common_control (pt[2]) == 0) { block_valid = 0; break; }
        if (is_valid_printable_32_incl_common_control (pt[3]) == 0) { block_valid = 0; break; }
      }

      if (block_valid == 0) continue;
    }
    else
    {
      // single-block: check all plaintext bytes (skip padding bytes)
      // paddingv = plaintext length (16 - pad_bytes)

      int pt_valid = 1;

      for (int i = 0; i < paddingv; i++)
      {
        const u32 idx = i / 4;
        const u32 shr = (i % 4) * 8;
        const u8  byte_val = (u8) (dec[idx] >> shr);

        if (is_valid_printable_8_incl_common_control (byte_val) == 0)
        {
          pt_valid = 0;
          break;
        }
      }

      if (pt_valid == 0) continue;
    }

    const u32 r0 = search[0];
    const u32 r1 = search[1];
    const u32 r2 = search[2];
    const u32 r3 = search[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m76000_sxx (KERN_ATTR_VECTOR_ESALT (cryptojs_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
  };

  /**
   * base
   */

  u32 s[2];

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const int data_len = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;

  u32 enc[4];

  enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].last_enc[0];
  enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].last_enc[1];
  enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].last_enc[2];
  enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].last_enc[3];

  u32 last_iv[4];

  last_iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].last_iv[0];
  last_iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].last_iv[1];
  last_iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].last_iv[2];
  last_iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].last_iv[3];

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[32] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    md5_ctx_t ctx;

    // D1 = MD5(password || salt)

    md5_init (&ctx);

    md5_update (&ctx, w, pw_len);

    u32 t[16];

    t[ 0] = s[0];
    t[ 1] = s[1];
    t[ 2] = 0;
    t[ 3] = 0;
    t[ 4] = 0;
    t[ 5] = 0;
    t[ 6] = 0;
    t[ 7] = 0;
    t[ 8] = 0;
    t[ 9] = 0;
    t[10] = 0;
    t[11] = 0;
    t[12] = 0;
    t[13] = 0;
    t[14] = 0;
    t[15] = 0;

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    u32 ukey[8];

    ukey[0] = ctx.h[0];
    ukey[1] = ctx.h[1];
    ukey[2] = ctx.h[2];
    ukey[3] = ctx.h[3];

    // D2 = MD5(D1 || password || salt)

    md5_init (&ctx);

    ctx.w0[0] = ukey[0];
    ctx.w0[1] = ukey[1];
    ctx.w0[2] = ukey[2];
    ctx.w0[3] = ukey[3];

    ctx.len = 16;

    md5_update (&ctx, w, pw_len);

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    ukey[4] = ctx.h[0];
    ukey[5] = ctx.h[1];
    ukey[6] = ctx.h[2];
    ukey[7] = ctx.h[3];

    // D3 = MD5(D2 || password || salt)

    u32 d2[4];

    d2[0] = ctx.h[0];
    d2[1] = ctx.h[1];
    d2[2] = ctx.h[2];
    d2[3] = ctx.h[3];

    md5_init (&ctx);

    ctx.w0[0] = d2[0];
    ctx.w0[1] = d2[1];
    ctx.w0[2] = d2[2];
    ctx.w0[3] = d2[3];

    ctx.len = 16;

    md5_update (&ctx, w, pw_len);

    md5_update (&ctx, t, 8);

    md5_final (&ctx);

    // D3 = derived IV (keep LE, no swap)

    u32 d3[4];

    d3[0] = ctx.h[0];
    d3[1] = ctx.h[1];
    d3[2] = ctx.h[2];
    d3[3] = ctx.h[3];

    // AES-256

    ukey[0] = hc_swap32_S (ukey[0]);
    ukey[1] = hc_swap32_S (ukey[1]);
    ukey[2] = hc_swap32_S (ukey[2]);
    ukey[3] = hc_swap32_S (ukey[3]);
    ukey[4] = hc_swap32_S (ukey[4]);
    ukey[5] = hc_swap32_S (ukey[5]);
    ukey[6] = hc_swap32_S (ukey[6]);
    ukey[7] = hc_swap32_S (ukey[7]);

    u32 ks[60];

    AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 dec[4];

    aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    // CBC XOR with IV

    u32 iv[4];

    if (data_len == 16)
    {
      iv[0] = d3[0];
      iv[1] = d3[1];
      iv[2] = d3[2];
      iv[3] = d3[3];
    }
    else
    {
      iv[0] = last_iv[0];
      iv[1] = last_iv[1];
      iv[2] = last_iv[2];
      iv[3] = last_iv[3];
    }

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int paddingv = pkcs_padding_bs16 (dec, 16);

    if (paddingv == -1) continue;

    // verify decrypted content is printable ASCII

    if (data_len > 16)
    {
      // multi-block: decrypt and check up to first_blocks_cnt blocks

      const int blocks_cnt = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks_cnt;

      int block_valid = 1;

      for (int b = 0; b < blocks_cnt; b++)
      {
        const int off = b * 4;

        u32 ct[4];

        ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[off + 0];
        ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[off + 1];
        ct[2] = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[off + 2];
        ct[3] = esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[off + 3];

        u32 pt[4];

        aes256_decrypt (ks, ct, pt, s_td0, s_td1, s_td2, s_td3, s_td4);

        // CBC XOR: first block uses derived IV, rest use previous ciphertext block

        if (b == 0)
        {
          pt[0] ^= d3[0];
          pt[1] ^= d3[1];
          pt[2] ^= d3[2];
          pt[3] ^= d3[3];
        }
        else
        {
          const int prev = (b - 1) * 4;

          pt[0] ^= esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[prev + 0];
          pt[1] ^= esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[prev + 1];
          pt[2] ^= esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[prev + 2];
          pt[3] ^= esalt_bufs[DIGESTS_OFFSET_HOST].first_blocks[prev + 3];
        }

        if (is_valid_printable_32_incl_common_control (pt[0]) == 0) { block_valid = 0; break; }
        if (is_valid_printable_32_incl_common_control (pt[1]) == 0) { block_valid = 0; break; }
        if (is_valid_printable_32_incl_common_control (pt[2]) == 0) { block_valid = 0; break; }
        if (is_valid_printable_32_incl_common_control (pt[3]) == 0) { block_valid = 0; break; }
      }

      if (block_valid == 0) continue;
    }
    else
    {
      // single-block: check all plaintext bytes (skip padding bytes)
      // paddingv = plaintext length (16 - pad_bytes)

      int pt_valid = 1;

      for (int i = 0; i < paddingv; i++)
      {
        const u32 idx = i / 4;
        const u32 shr = (i % 4) * 8;
        const u8  byte_val = (u8) (dec[idx] >> shr);

        if (is_valid_printable_8_incl_common_control (byte_val) == 0)
        {
          pt_valid = 0;
          break;
        }
      }

      if (pt_valid == 0) continue;
    }

    const u32 r0 = search[0];
    const u32 r1 = search[1];
    const u32 r2 = search[2];
    const u32 r3 = search[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
