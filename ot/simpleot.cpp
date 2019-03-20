#include "simpleot.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/crypto/pk-crypto.h>
#include <cstdlib>

void SimpleOT::Receiver([[maybe_unused]] uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, uint8_t* retbuf) {

	fe *g, **B, *A, *AB;
	num **b, *order, *tmp;
	uint8_t *sndbuf, *sndbufptr, *rcvbuf, *retbufptr, *tmpbuf;

	brickexp* bg;
	uint32_t i, sndbufsize, hash_bytes, fe_bytes;

	hash_bytes = m_cCrypto->get_hash_bytes();
	fe_bytes = m_cPKCrypto->fe_byte_size();

	//use default generator and init brick
	g = m_cPKCrypto->get_generator();
	bg = m_cPKCrypto->get_brick(g);

	order = m_cPKCrypto->get_order();

	b = (num**) malloc(sizeof(num*) * nOTs);
	B = (fe**) malloc(sizeof(fe*) * nOTs);

	tmp = m_cPKCrypto->get_num();
	A = m_cPKCrypto->get_fe();
	//Receive A values
	rcvbuf = chan->blocking_receive();

	sndbufsize = nOTs * fe_bytes;
	sndbuf = (uint8_t*) malloc(sndbufsize);
	sndbufptr = sndbuf;

	A->import_from_bytes(rcvbuf);
	//TODO: very timing side channel affine
	for(i = 0; i < nOTs; i++, sndbufptr+=fe_bytes) {
		b[i] = m_cPKCrypto->get_rnd_num();
		b[i]->mod(order);
		B[i] = m_cPKCrypto->get_fe();

		if(choices->GetBit(i) == 0) {
			bg->pow(B[i] , b[i]);
			B[i]->export_to_bytes(sndbufptr);
		} else {
			tmp->set_sub(order, b[i]);
			bg->pow(B[i], tmp);
			AB = m_cPKCrypto->get_fe();
			AB->set_mul(B[i], A);
			AB->export_to_bytes(sndbufptr);
			delete AB;
		}
	}

	chan->send(sndbuf, sndbufsize);
	free(sndbuf);

	retbufptr = retbuf;
	tmpbuf = (uint8_t*) malloc(fe_bytes);
	AB = m_cPKCrypto->get_fe();
	for(i = 0; i < nOTs; i++, retbufptr+=hash_bytes) {
		AB->set_pow(A, b[i]);
		AB->export_to_bytes(tmpbuf);

		hashReturn(retbufptr, hash_bytes, tmpbuf, fe_bytes, i);
	}

	free(tmpbuf);
	free(rcvbuf);
	for(uint32_t i = 0; i < nOTs; i++) {
		delete b[i];
		delete B[i];
	}
	free(b);
	free(B);

	delete bg;

	delete g;
	delete A;
	delete AB;
	delete order;
	delete tmp;
}


void SimpleOT::Sender([[maybe_unused]] uint32_t nSndVals, uint32_t nOTs, channel* chan, uint8_t* retbuf) {
	fe *g, *A, *Asqr, *B, *AB, *tmp;
	num *a, *asqr, *order;

	brickexp *bg;

	uint8_t *sndbuf, *sndbufptr, *rcvbuf, *rcvbufptr, *retbufptr, *tmpbuf;

	uint32_t i, sndbufsize, fe_bytes, hash_bytes;

	hash_bytes = m_cCrypto->get_hash_bytes();
	fe_bytes = m_cPKCrypto->fe_byte_size();

	//use default generator and init brick
	g = m_cPKCrypto->get_generator();
	bg = m_cPKCrypto->get_brick(g);

	a = m_cPKCrypto->get_rnd_num();
	A = m_cPKCrypto->get_fe();

	sndbufsize = fe_bytes;
	sndbuf = (uint8_t*) malloc(sndbufsize);
	sndbufptr = sndbuf;

	bg->pow(A, a);
	A->export_to_bytes(sndbufptr);

	chan->send(sndbuf, sndbufsize);
	free(sndbuf);

	asqr = m_cPKCrypto->get_num();
	Asqr = m_cPKCrypto->get_fe();

	order = m_cPKCrypto->get_order();
	asqr->set_mul_mod(a, a, order);
	delete order;
	bg->pow(Asqr, asqr);
	//Asqr->set_pow(g, asqr);


	rcvbuf = chan->blocking_receive();
	tmpbuf = (uint8_t*) malloc(fe_bytes);

	rcvbufptr = rcvbuf;
	retbufptr = retbuf;

	for(i = 0; i < nOTs; i++, rcvbufptr+=fe_bytes) {
		B = m_cPKCrypto->get_fe();
		B->import_from_bytes(rcvbufptr);
		//cout << "B: "; B->print();
		//cout << "A[i]: "; A[i]->print();
		//cout << "a[i]: "; a[i]->print();

		//For X0
		AB = m_cPKCrypto->get_fe();
		AB->set_pow(B, a);
		AB->export_to_bytes(tmpbuf);
		hashReturn(retbufptr, hash_bytes, tmpbuf, fe_bytes, i);
		retbufptr+=hash_bytes;

		//For X1
		//AB = m_cPKCrypto->get_fe();
		tmp = m_cPKCrypto->get_fe();
		tmp->set_div(Asqr, AB);
		tmp->export_to_bytes(tmpbuf),
		hashReturn(retbufptr, hash_bytes, tmpbuf, fe_bytes, i);
		retbufptr+=hash_bytes;

		delete AB;
		delete B;
		delete tmp;
	}

	free(tmpbuf);
	free(rcvbuf);
	delete bg;

	delete g;
	delete A;
	delete Asqr;
	delete a;
	delete asqr;
}
