#include <pbc/pbc.h>
#define PK_INIT 0
#define PK_EXISTED 1

// BN254
#define ZP_BYTES_LEN 32
#define GONE_BYTES_LEN 33
#define GTWO_BYTES_LEN 65
#define GT_BYTES_LEN 384
#define IV_LEN 12
#define KEY_LEN 16
#define TAG_LEN 16

#define MIN_UNIT_LEN sizeof(unsigned char)
#define COUNT_MARK_LEN sizeof(int)
#define PP_BYTES_LEN (5 * GONE_BYTES_LEN + GTWO_BYTES_LEN + GT_BYTES_LEN)
#define ISK_UNIT_LEN (2 * ZP_BYTES_LEN + GONE_BYTES_LEN + GTWO_BYTES_LEN)
#define SK_UNIT_LEN (ZP_BYTES_LEN + GONE_BYTES_LEN + GTWO_BYTES_LEN)
#define TK_UNIT_LEN SK_UNIT_LEN
#define IT_UNIT_LEN (3 * ZP_BYTES_LEN + 2 * GONE_BYTES_LEN + GTWO_BYTES_LEN)
#define IT_UNIQUE_LEN (ZP_BYTES_LEN + GT_BYTES_LEN + GTWO_BYTES_LEN)
#define CT_UNIT_LEN (2 * GONE_BYTES_LEN + GTWO_BYTES_LEN + 2 * ZP_BYTES_LEN)
#define CT_UNIQUE_LEN GTWO_BYTES_LEN
#define RCT_UNIT_LEN CT_UNIT_LEN
#define RCT_UNIQUE_LEN (2 * GTWO_BYTES_LEN + ZP_BYTES_LEN + GONE_BYTES_LEN + GT_BYTES_LEN)
#define HRCT_NORMAL_LEN GT_BYTES_LEN
#define HRCT_REENC_LEN (2 * GT_BYTES_LEN + GONE_BYTES_LEN + GTWO_BYTES_LEN + ZP_BYTES_LEN)

struct PK
{
    element_t g1;
    element_t g2;
    element_t h;
    element_t u;
    element_t v;
    element_t w;
    element_t e_alpha;
    pairing_t pairing;
    unsigned char *common_attr;
    size_t common_attr_len;
};

struct MSK
{
    struct PK *pk;
    element_t alpha;
};

struct ISK
{
    element_t _alpha;
    element_t _r;
    element_t _K0;
    element_t _K1;
    element_t *r_;
    element_t *a_;
    element_t *_K2;
    element_t *_K3;
    int num;
};

struct SK
{
    struct PK *pk;
    unsigned char **S;
    unsigned char *_attr;
    element_t K0;
    element_t K1;
    element_t K4;
    element_t *K2;
    element_t *K3;
    element_t *K5;
    int num;
};

struct IT
{
    element_t _s;
    element_t _C;
    element_t _C0;
    element_t *_lambda;
    element_t *_t;
    element_t *_x;
    element_t *C1_;
    element_t *C2_;
    element_t *C3_;
    int num;
};

struct RK
{
    struct PK *pk;
    struct SK *key;
    element_t rk;
    struct CT *cipher;
    int key_attr_num;
    int policy_attr_num;
};

struct CT
{
    struct PK *pk;
    unsigned char *policy;
    element_t C0;
    element_t *C1;
    element_t *C2;
    element_t *C3;
    element_t *C4;
    element_t *C5;
    int num;
};

struct RCT
{
    struct PK *pk;
    unsigned char *policy;
    element_t _K4;
    element_t _C;
    element_t C0;
    element_t rk;
    element_t _C0;
    element_t *C1_;
    element_t *C2_;
    element_t *C3_;
    element_t *C4_;
    element_t *C5_;
    int num;
};

int get_attr_num_from_set(unsigned char *attr);
int get_policy_count(const char *policy_str);
int iie_abe_setup(struct PK *pk, struct MSK *msk, unsigned char *pp_buf_ptr, unsigned char *msk_buf, unsigned char *dft_str, int mode, int *ret_len);
int iie_abe_keygen_out(struct PK *pk, unsigned char *isk_buf, int N, int *ret_len);
int iie_abe_keygen_pkg(struct MSK *msk, unsigned char *attr, unsigned char *isk1_buf, unsigned char *isk2_buf, unsigned char *sk_buf, int *ret_len);
int iie_abe_keygen_ran(struct PK *pk, unsigned char *sk_buf, unsigned char *tk_buf, unsigned char *rtk_buf, int *ret_len);
int iie_abe_encrypt_out(struct PK *pk, unsigned char *it_buf, int N, int *ret_len);
int iie_abe_encrypt_user(struct PK *pk, unsigned char *it1_buf, unsigned char *it2_buf, unsigned char *ct_buf, unsigned char *policy, unsigned char *plaintext, int *ret_len);
int iie_abe_rkeygen(struct PK *pk, unsigned char *isk1_buf, unsigned char *isk2_buf, unsigned char *it1_buf, unsigned char *it2_buf, unsigned char *sk_buf, unsigned char *rk_buf, unsigned char *policy, int *ret_len);
int iie_abe_re_enc(struct PK *pk, unsigned char *cipher, unsigned char *rk_buf, int cipher_len, int abe_rct_len, unsigned char *rct_buf, int *ret_len);
int iie_abe_decrypt_out(struct PK *pk, unsigned char *tk_buf, unsigned char *cipher, int ct_len, unsigned char *hrct_buf, int *ret_len);
int iie_abe_decrypt_user(struct PK *pk, unsigned char *rtk_buf, unsigned char *cipher, int cipher_len, unsigned char *plaintext, int *ret_len);
int iie_abe_clear_params(struct PK *pk, struct MSK *msk);
int iie_abe_add(int a, int b);