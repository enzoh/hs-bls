#define MCLBN_FP_UNIT_SIZE 6
#include <bls/bls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IN(t, x, s, n) \
  bls ## t x[1]; \
  bls ## t ## Deserialize(x, s, n)

#define OUT(t, x) \
  enum { bufsz = 65 }; \
  char *buf_ = malloc(bufsz); \
  memset(buf_, 0, bufsz); \
  *buf_ = bls ## t ## Serialize(buf_ + 1, bufsz - 1, x); \
  return buf_

void shimInit() { blsInit(0, MCLBN_FP_UNIT_SIZE); }

char *frmapnew(char *s, int slen) {
  blsSecretKey x[1];
  blsHashToSecretKey(x, s, slen);
  OUT(SecretKey, x);
}

char *fromSecretNew(char *s, int slen) {
  IN(SecretKey, x, s, slen);
  blsPublicKey gx[1];
  blsGetPublicKey(gx, x);
  OUT(PublicKey, gx);
}

char *blsSignatureNew(char *s, int slen, char* m, int mlen) {
  IN(SecretKey, x, s, slen);
  blsSignature sig[1];
  blsSign(sig, x, m, mlen);
  OUT(Signature, sig);
}

char *shimSign(char *s, int slen, char *m, int mlen) {
  IN(SecretKey, x, s, slen);
  blsSignature sig[1];
  blsSign(sig, x, m, mlen);
  OUT(Signature, sig);
}

int shimVerify(char *s, int slen, char *t, int tlen, char *m, int mlen) {
  IN(Signature, hx, s, slen);
  IN(PublicKey, gx, t, tlen);
  return blsVerify(hx, gx, m, mlen);
}

char *getPopNew(char* t, int tlen) {
  IN(SecretKey, x, t, tlen);
  blsSignature sig[1];
  blsGetPop(sig, x);
  OUT(Signature, sig);
}

int shimVerifyPop(char *s, int slen, char *t, int tlen) {
  IN(Signature, sig, s, slen);
  IN(PublicKey, pub, t, tlen);
  return blsVerifyPop(sig, pub);
}

struct dkg {
  int t;
  blsPublicKey gpk[1];
  blsPublicKey *pk;
  blsSecretKey *sk;
};

void *dkgNew(int t) {
  struct dkg* r = malloc(sizeof(struct dkg));
  r->pk = malloc(sizeof(blsPublicKey) * t);
  r->sk = malloc(sizeof(blsSecretKey) * t);
  r->t = t;
  int i;
  for (i = 0; i < t; i++) {
    blsSecretKeySetByCSPRNG(r->sk + i);
    blsGetPublicKey(r->pk + i, r->sk + i);
  }
  blsId id0[1];
  blsIdSetInt(id0, 0);
  blsPublicKeyShare(r->gpk, r->pk, t, id0);
  return r;
}

void dkgFree(struct dkg* r) {
  free(r->pk);
  free(r->sk);
  free(r);
}

char *dkgPublicKeyNew(struct dkg* p) {
  OUT(PublicKey, p->gpk);
}

char *dkgSecretShareNew(struct dkg* p, int i) {
  if (!i) {
    fprintf(stderr, "BUG: ID = 0\n");
    exit(1);
  }
  blsId id[1];
  blsIdSetInt(id, i);
  blsSecretKey sh[1];
  blsSecretKeyShare(sh, p->sk, p->t, id);
  OUT(SecretKey, sh);
}

char *dkgGroupPublicKeyNew(struct dkg* p) {
  OUT(PublicKey, p->gpk);
}

struct sigshare {
  int t;
  int i;
  blsSignature *sig;
  blsId *id;
};

void *signatureShareNew(int t) {
  struct sigshare *r = malloc(sizeof(struct sigshare));
  r->t = t;
  r->i = 0;
  r->sig = malloc(sizeof(blsSignature) * t);
  r->id = malloc(sizeof(blsId) * t);
  return r;
}

void signatureShareFree(struct sigshare *p) {
  free(p->sig);
  free(p->id);
  free(p);
}

void signatureShareAdd(struct sigshare *p, int i, char *sig, int siglen) {
  if (p->i == p->t) {
    fprintf(stderr, "BUG: too many signature shares\n");
    exit(1);
  }
  blsSignatureDeserialize(p->sig + p->i, sig, siglen);
  blsIdSetInt(p->id + p->i, i);
  p->i++;
}

char *recoverSignatureNew(struct sigshare *p) {
  if (p->i != p->t) {
    fprintf(stderr, "BUG: too few signature shares\n");
    exit(1);
  }
  blsSignature sig[1];
  blsSignatureRecover(sig, p->sig, p->id, p->t);
  OUT(Signature, sig);
}
