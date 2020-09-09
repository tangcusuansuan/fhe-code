#include <bits/stdc++.h>

#include "palisade.h"
using namespace lbcrypto;
using namespace std;

string rootf = "../../eg/data/";

// plain text
typedef vector<complex<double> > varr;

const int imsz = 28 * 28;
const int neurons = 10;

varr W_raw;
vector<varr> W; // reshaped
varr b;
vector<varr> data;

void read_data(const string& path, varr& a) {
  ifstream ifs(path.c_str());
  double d;
  while(ifs>>d)  {
    a.push_back(d);
  }
  ifs.close();
}

void load_data() {
  read_data(rootf + "w.txt",W_raw);
  read_data(rootf + "b.txt",b);
  for(int i = 0; i < 10; i++) {
    string p = rootf + char(i + '0') + ".txt";
    data.push_back(varr());
    read_data(p, data.back());
  }
  printf("W.shape = (%lu, )\n", W_raw.size());
  printf("b.shape = (%lu, )\n", b.size());
  printf("data[0].shape = (%lu, )\n", data[0].size());

  for(int i = 0; i < imsz; i++) {
    for(int j = 0; j < neurons; j++) {
      if((int)W.size() <= j) W.push_back(varr());
      W[j].push_back(W_raw[i * neurons + j]);
      if(W[j][i] != W_raw[i * neurons + j]) {
        printf("Error: invalid value\n");
        exit(-1);
      }
    }
  }
  printf("W[0].shape = (%lu, )\n", W[0].size());

}

void raw_eval() {
  // perform raw evaluation
  for(int d = 0; d < 10; d++) { // for each data
    double m = std::numeric_limits<double>::lowest();
    int idx = -1;
    for(int n = 0; n < neurons; n++) { // for each neuron
      auto c = b[0];
      for(int i = 0; i < imsz; i++) {
        c += W[n][i] * data[d][i];
      }
      if(c.real() > m) {
        m = c.real();
        idx = n;
      }
    }
    printf("Raw Predicted %d for data %d\n", idx, d);
  }
}

void he_pred() {
  uint32_t multDepth = 3; // should be enough...
  uint32_t scaleFactorBits = 50;
	uint32_t batchSize = 28*28;

	SecurityLevel securityLevel = HEStd_128_classic;

	CryptoContext<DCRTPoly> cc =
			CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
			   multDepth,
			   scaleFactorBits,
			   batchSize,
			   securityLevel);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);
  cc->EvalSumKeyGen(keys.secretKey);
	cc->EvalAtIndexKeyGen(keys.secretKey, { -1 });

  typedef vector<Plaintext> pvarr;
  pvarr W_p;
  pvarr data_p;
  Plaintext b_p;
  for(int i = 0; i < neurons; i++) {
    Plaintext p = cc->MakeCKKSPackedPlaintext(W[i]);
    W_p.push_back(p);
  }
  for(int d = 0; d < 10; d++) {
    Plaintext p = cc->MakeCKKSPackedPlaintext(data[d]);
    data_p.push_back(p);
  }
  b_p = cc->MakeCKKSPackedPlaintext(b);

  auto b_e = cc->Encrypt(keys.publicKey, b_p);

  typedef decltype(b_e) Encrypted;
  typedef vector<Encrypted> evarr;

  evarr W_e;
  evarr data_e;
  for(int i = 0; i < neurons; i++) {
    W_e.push_back(cc->Encrypt(keys.publicKey, W_p[i]));
  }
  for(int d = 0; d < 10; d++) {
    data_e.push_back(cc->Encrypt(keys.publicKey, data_p[d]));
  }

  printf("Encryption Done, Performing op\n");

  // encryption done
  for(int d = 0; d < 10; d++) {
    auto r = b_e;
    for(int i = neurons - 1; i >= 0; i--) {
      auto c = cc->EvalMult(W_e[i], data_e[d]);
      c = cc->EvalSum(c, batchSize);
      c = cc->EvalAtIndex(c, -1); // >> 1
      r = cc->EvalAdd(r, c);
    }
    // now r is the W * data + b, we decrypt it
    Plaintext result;
    cc->Decrypt(keys.secretKey, r, &result);
    auto v = result->GetCKKSPackedValue();
    double m = std::numeric_limits<double>::lowest();
    int idx = -1;
    for(int i = 0; i < neurons; i++) {
      auto x = v[i];
      if(x.real() > m) {
        m = x.real();
        idx = i;
      }
    }
    printf("FHE Predicted %d for data %d\n", idx, d);

  }


}

int main() {

  load_data();
  raw_eval();
  he_pred();

  /*
  
  uint32_t multDepth = 2; // should be enough...
  uint32_t scaleFactorBits = 50;
	uint32_t batchSize = 28*28;

	SecurityLevel securityLevel = HEStd_128_classic;

	CryptoContext<DCRTPoly> cc =
			CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
			   multDepth,
			   scaleFactorBits,
			   batchSize,
			   securityLevel);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);

  vector<complex<double>> x1 = { 0.12, 0.33 };
  vector<complex<double>> x2 = { 0.3, 0.2 };

  Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
  Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

	cout << "Input x1: " << ptxt1 << endl;
	cout << "Input x2: " << ptxt2 << endl;

	auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
	auto c2 = cc->Encrypt(keys.publicKey, ptxt2);
	auto cMul = cc->EvalMult(c1, c2);

	Plaintext result;

	cc->Decrypt(keys.secretKey, cMul, &result);

	result->SetLength(batchSize);

	cout << "x1 * x2 = " << result << endl;
  */


  return 0;
}
