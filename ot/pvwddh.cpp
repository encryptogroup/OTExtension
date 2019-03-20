#include "pvwddh.h"
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/cbitvector.h>
#include <iostream>

void PVWDDH::Receiver([[maybe_unused]] uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, uint8_t* retbuf) {

	fe *g[2], *h[2], *pkg, *pkh, *u, *zkcommit[2];
	num *y, *alpha, *r[nOTs], *zkr, *zkchallenge, *zkproof;
	uint8_t *sndbuf, *sndbufptr, *rcvbuf, *rcvbufptr, *retbufptr, *tmpbuf;

	brickexp* bg[2];
	brickexp* bh[2];
	uint32_t i, sndbufsize, hash_bytes, fe_bytes, num_bytes;

	hash_bytes = m_cCrypto->get_hash_bytes();
	fe_bytes = m_cPKCrypto->fe_byte_size();
	num_bytes = m_cPKCrypto->num_byte_size();

	//First step: do initial crs exchange
	sndbufsize = fe_bytes * 6;
	sndbuf = (uint8_t*) malloc(sndbufsize);

	for(i = 0; i < 2; i++) {
		g[i] = m_cPKCrypto->get_fe();
		h[i] = m_cPKCrypto->get_fe();
		zkcommit[i] = m_cPKCrypto->get_fe();
	}

	//use default generator and init brick
	g[0] = m_cPKCrypto->get_generator();
	bg[0] = m_cPKCrypto->get_brick(g[0]);

	//generate random y and alpha
	y = m_cPKCrypto->get_rnd_num();
	alpha = m_cPKCrypto->get_rnd_num();


	//compute g1 = g0 ^ y and init brick
	bg[0]->pow(g[1], y);
	bg[1] = m_cPKCrypto->get_brick(g[1]);

	//sample random rzk for zero-knowledge proof
	zkr = m_cPKCrypto->get_rnd_num();

	sndbufptr = sndbuf;

	//compute h0 = g0 ^ alpha and h1 = g1 ^ alpha
	for(i = 0; i < 2; i++) {
		bg[i]->pow(h[i], alpha);
		bh[i] = m_cPKCrypto->get_brick(h[i]);

		//Convert field elements to bytes
		g[i]->export_to_bytes(sndbufptr);
		sndbufptr+=fe_bytes;
		h[i]->export_to_bytes(sndbufptr);
		sndbufptr+=fe_bytes;

		//ZK-proof data
		bg[i]->pow(zkcommit[i], zkr);
		zkcommit[i]->export_to_bytes(sndbufptr);
		sndbufptr+=fe_bytes;
	}

	//send public keys together with proofs to the sender
	chan->send(sndbuf, sndbufsize);
	free(sndbuf);


	//Second step: for each OT generate and send a public-key and receive challenge + send compute proof
	pkg = m_cPKCrypto->get_fe();
	pkh = m_cPKCrypto->get_fe();

	sndbufsize = fe_bytes * 2 * nOTs + num_bytes;
	sndbuf = (uint8_t*) malloc(sndbufsize);
	sndbufptr = sndbuf;

	for(i = 0; i < nOTs; i++) {
		//generate r_i at random and compute g_i = g_sigma_i ^ r_i and h_i = h_sigma_i ^ r_i
		r[i] = m_cPKCrypto->get_rnd_num();
		bg[choices->GetBit(i)]->pow(pkg, r[i]);
		bh[choices->GetBit(i)]->pow(pkh, r[i]);

		//convert elements to bytes
		pkg->export_to_bytes(sndbufptr);
		sndbufptr+=fe_bytes;
		pkh->export_to_bytes(sndbufptr);
		sndbufptr+=fe_bytes;
	}

	//Receive challenge
	rcvbuf = chan->blocking_receive();
	zkchallenge = m_cPKCrypto->get_num();
	zkchallenge->import_from_bytes(rcvbuf, num_bytes);
	free(rcvbuf);

	//Compute proof as zkproof = (zkr + zkchallenge * alpha ) mod q
	zkproof = m_cPKCrypto->get_num();
	zkproof->set_mul_mod(alpha, zkchallenge, m_cPKCrypto->get_order());
	zkproof->set_add(zkproof, zkr);
	zkproof->mod(m_cPKCrypto->get_order());
	zkproof->export_to_bytes(sndbufptr, num_bytes);

	//send data and proof
	chan->send(sndbuf, sndbufsize);


	//Third step: receive the seeds to the KDF from the sender and generate a random string from the chosen one
	u = m_cPKCrypto->get_fe();

	//receive the values
	//rcvbufsize = 2 * nOTs * fe_bytes;
	rcvbuf = chan->blocking_receive();

	//a buffer for storing the hash input
	tmpbuf = (uint8_t*) malloc(fe_bytes);

	retbufptr = retbuf;
	rcvbufptr = rcvbuf;

	for (i = 0; i < nOTs; i++, rcvbufptr+=(2 * fe_bytes), retbufptr+=hash_bytes) {
		//convert the received bytes to a field element, compute u_i ^ r_i, and convert u_i^r_i back to bytes
		u->import_from_bytes(rcvbufptr + (choices->GetBit(i) * fe_bytes));
		u->set_pow(u, r[i]);
		u->export_to_bytes(tmpbuf);

		//hash u_i^r_i
		hashReturn(retbufptr, hash_bytes, tmpbuf, fe_bytes, i);
	}

	for(i = 0; i < 2; i++) {
		delete bg[i];
		delete bh[i];
	}

	free(sndbuf);
	free(rcvbuf);
	free(tmpbuf);
}


void PVWDDH::Sender([[maybe_unused]] uint32_t nSndVals, uint32_t nOTs, channel* chan, uint8_t* retbuf) {
	fe *g[2], *h[2], *pkg, *pkh, *u, *v, *gs, *ht, *zkcommit[2], *gchk, *zkchk;
	num *s, *t, *zkchallenge, *zkproof;

	brickexp *bg[2];
	brickexp *bh[2];

	uint8_t *sndbuf, *sndbufptr, *rcvbuf, *rcvbufptr, *retbufptr, *tmpbuf;

	uint32_t i, j, sndbufsize, fe_bytes, num_bytes, hash_bytes;

	hash_bytes = m_cCrypto->get_hash_bytes();
	fe_bytes = m_cPKCrypto->fe_byte_size();
	num_bytes = m_cPKCrypto->num_byte_size();

	//First step: receive the crs and initialize the bricks
	zkchallenge = m_cPKCrypto->get_rnd_num();

	rcvbuf = chan->blocking_receive();

	//Send challenge
	sndbuf = (uint8_t*) malloc(num_bytes);
	zkchallenge->export_to_bytes(sndbuf, num_bytes);
	chan->send(sndbuf, num_bytes);
	free(sndbuf);

	rcvbufptr = rcvbuf;
	for(i = 0; i < 2; i++) {
		g[i] = m_cPKCrypto->get_fe();
		g[i]->import_from_bytes(rcvbufptr);
		rcvbufptr += fe_bytes;
		bg[i] = m_cPKCrypto->get_brick(g[i]);

		h[i] = m_cPKCrypto->get_fe();
		h[i]->import_from_bytes(rcvbufptr);
		rcvbufptr += fe_bytes;
		bh[i] = m_cPKCrypto->get_brick(h[i]);

		//Zero-knowledge commits
		zkcommit[i] = m_cPKCrypto->get_fe();
		zkcommit[i]->import_from_bytes(rcvbufptr);
		rcvbufptr += fe_bytes;
	}

	free(rcvbuf);

	//Second step: receive a public-key for each OT
	pkg = m_cPKCrypto->get_fe();
	pkh = m_cPKCrypto->get_fe();
	u = m_cPKCrypto->get_fe();
	v = m_cPKCrypto->get_fe();
	gs = m_cPKCrypto->get_fe();
	ht = m_cPKCrypto->get_fe();

	rcvbuf = chan->blocking_receive();

	sndbufsize = 2 * nOTs * fe_bytes;
	sndbuf = (uint8_t*) malloc(sndbufsize);

	tmpbuf = (uint8_t*) malloc(fe_bytes);

	rcvbufptr = rcvbuf;
	sndbufptr = sndbuf;
	retbufptr = retbuf;

	for(i = 0; i < nOTs; i++) {
		//read pkg_i and pkh_i
		pkg->import_from_bytes(rcvbufptr);
		rcvbufptr += fe_bytes;
		pkh->import_from_bytes(rcvbufptr);
		rcvbufptr += fe_bytes;


		for(j = 0; j < 2; j++) {
			//choose random si and ti
			s = m_cPKCrypto->get_rnd_num();
			t = m_cPKCrypto->get_rnd_num();

			//u_i = g_j^s_i * h_j ^ t_i
			bg[j]->pow(gs, s);
			bh[j]->pow(ht, t);
			u = m_cPKCrypto->get_fe();//TODO: there is sth weird going on here, get new fe to avoid this problem
			u->set_mul(gs, ht);

			v = m_cPKCrypto->get_fe();//TODO: there is sth weird going on here, get new fe to avoid this problem
			//v_i = pkg_i^s_i * pkh_i ^ t_i
			v->set_double_pow_mul(pkg, s, pkh, t);

			//store u_i in the sndbuf
			u->export_to_bytes(sndbufptr);
			sndbufptr+=fe_bytes;

			v->export_to_bytes(tmpbuf);
			hashReturn(retbufptr, hash_bytes, tmpbuf, fe_bytes, i);
			retbufptr+=hash_bytes;
		}
	}

	zkproof = m_cPKCrypto->get_num();

	//send the u_i's
	chan->send(sndbuf, sndbufsize);

	//Verify proof
	zkproof->import_from_bytes(rcvbufptr, num_bytes);

	//Group check is omitted because both parties use the pre-generated NIST parameters
	gchk = m_cPKCrypto->get_fe();
	zkchk = m_cPKCrypto->get_fe();

	for(j = 0; j < 2; j++) {
		//gj ^ zkproof
		bg[j]->pow(gchk, zkproof);

		//zkcommit_j * h_j^zkchallenge
		bh[j]->pow(zkchk, zkchallenge);
		zkchk->set_mul(zkchk, zkcommit[j]);

		//if(gchk != zkchk) {
		if(!gchk->eq(zkchk)) {
			std::cout << "Zero-knowledge proof for base-OTs failed!" << std::endl;
			gchk->print();
			std::cout << ", vs. ";
			zkchk->print();
			std::cout << std::endl;
			exit(0);
		}
	}

	for(i = 0; i < 2; i++) {
		delete bg[i];
		delete bh[i];
	}

	free(rcvbuf);
	free(sndbuf);
	free(tmpbuf);
}
