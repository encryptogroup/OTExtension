/**
 \file 		ot-extension.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		Methods for the OT Extension routine
 */

#ifndef __OT_EXTENSION_H_
#define __OT_EXTENSION_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../util/thread.h"
#include "../util/cbitvector.h"
#include "../util/crypto/crypto.h"
#include "maskingfunction.h"
#include "../util/constants.h"

static void InitAESKey(AES_KEY_CTX* ctx, BYTE* keybytes, uint32_t numkeys, crypto* crypt) {
	BYTE* pBufIdx = keybytes;
	uint32_t aes_key_bytes = crypt->get_aes_key_bytes();
	for (uint32_t i = 0; i < numkeys; i++) {
		crypt->init_aes_key(ctx + i, pBufIdx);
		pBufIdx += aes_key_bytes;
	}
}

struct ot_block {
	uint64_t startotid;
	uint64_t otlen;
	uint8_t* buf;
};

//A receive task listens to a particular id and writes incoming data on that id into rcv_buf and triggers event
struct rcv_task {
	std::queue<uint8_t*> *rcv_buf;
	CEvent* rcv_event;
	CEvent* fin_event;
	BOOL inuse;
};

//A receive task sends data on a particular id
struct snd_task {
	uint8_t channelid;
	uint64_t bytelen;
	uint8_t* snd_buf;
};

class RcvThread: public CThread {
public:
	RcvThread(CSocket* sock) {
		mysock = sock;
		rcvlock = new CLock();
		listeners = (rcv_task*) calloc(MAX_NUM_COMM_CHANNELS, sizeof(rcv_task));
		for(uint32_t i = 0; i < MAX_NUM_COMM_CHANNELS; i++) {
			listeners[i].rcv_buf = new queue<uint8_t*>;
		}
		listeners[ADMIN_CHANNEL].inuse = true;
	}
	;
	~RcvThread() {
		delete rcvlock;
		free(listeners);
	}
	;
	queue<uint8_t*>* add_listener(uint8_t channelid, CEvent* rcv_event, CEvent* fin_event) {
		rcvlock->Lock();
		if(listeners[channelid].inuse || channelid == ADMIN_CHANNEL) {
			cout << "A listener has already been registered on channel " << (uint32_t) channelid << endl;
			//assert(listeners[channelid].inuse || channelid == ADMIN_CHANNEL);
		}

		//listeners[channelid].rcv_buf = rcv_buf;
		listeners[channelid].rcv_event = rcv_event;
		listeners[channelid].fin_event = fin_event;
		listeners[channelid].inuse = true;
		cout << "Successfully registered on channel " << (uint32_t) channelid << endl;

		rcvlock->Unlock();
		return listeners[channelid].rcv_buf;
	}

	void ThreadMain() {
		uint8_t channelid;
		uint64_t rcvbytelen;
		uint8_t* tmprcvbuf;
		while(true) {
			mysock->Receive(&channelid, sizeof(uint8_t));
			mysock->Receive(&rcvbytelen, sizeof(uint64_t));
			cout << "Received value on channel " << (uint32_t) channelid << " with " << rcvbytelen << " bytes length" << endl;

			if(channelid == ADMIN_CHANNEL) {
				tmprcvbuf = (uint8_t*) malloc(rcvbytelen);
				mysock->Receive(tmprcvbuf, rcvbytelen);
				//TODO: Right now finish, can be used for other maintenance tasks
				free(tmprcvbuf);
				cout << "Got message on Admin channel, shutting down" << endl;
				continue;
			}

			if(rcvbytelen == 0) {
				listeners[channelid].fin_event->Set();
				if(listeners[channelid].inuse)
					listeners[channelid].inuse = false;
			} else {
				tmprcvbuf = (uint8_t*) malloc(rcvbytelen);
				mysock->Receive(tmprcvbuf, rcvbytelen);

				listeners[channelid].rcv_buf->push(tmprcvbuf);
				if(listeners[channelid].inuse)
					listeners[channelid].rcv_event->Set();
			}

		}
	}
	;
private:
	CLock* rcvlock;
	CSocket* mysock;
	rcv_task* listeners;
};


class SndThread: public CThread {
public:
	SndThread(CSocket* sock) {
		mysock = sock;
		sndlock = new CLock();
		send = new CEvent();
	}
	;
	~SndThread() {
		delete sndlock;
		delete send;
	}
	;

	void add_snd_task_start_len(uint8_t channelid, uint64_t sndbytes, uint8_t* sndbuf, uint64_t startid, uint64_t len) {
		snd_task* task = (snd_task*) malloc(sizeof(snd_task));
		assert(channelid != ADMIN_CHANNEL);
		task->channelid = channelid;
		task->bytelen = sndbytes + 2 * sizeof(uint64_t);
		task->snd_buf = (uint8_t*) malloc(task->bytelen);
		memcpy(task->snd_buf, &startid, sizeof(uint64_t));
		memcpy(task->snd_buf+sizeof(uint64_t), &len, sizeof(uint64_t));
		memcpy(task->snd_buf+2*sizeof(uint64_t), sndbuf, sndbytes);

		cout << "Adding a new task that is supposed to send " << task->bytelen << " bytes on channel " << (uint32_t) channelid  << endl;

		sndlock->Lock();
		send_tasks.push(task);
		sndlock->Unlock();
		send->Set();
	}


	void add_snd_task(uint8_t channelid, uint64_t sndbytes, uint8_t* sndbuf) {
		snd_task* task = (snd_task*) malloc(sizeof(snd_task));
		assert(channelid != ADMIN_CHANNEL);
		task->channelid = channelid;
		task->bytelen = sndbytes;
		task->snd_buf = (uint8_t*) malloc(sndbytes);
		memcpy(task->snd_buf, sndbuf, task->bytelen);

		sndlock->Lock();
		send_tasks.push(task);
		sndlock->Unlock();
		send->Set();
		cout << "Event set" << endl;

	}

	void signal_end(uint8_t channelid) {
		uint8_t dummy_val;
		add_snd_task(channelid, 0, &dummy_val);
		cout << "Signalling end on channel " << (uint32_t) channelid << endl;
	}

	void kill_task() {
		snd_task* task = (snd_task*) malloc(sizeof(snd_task));
		task->channelid = ADMIN_CHANNEL;
		task->bytelen = 1;
		task->snd_buf = (uint8_t*) malloc(1);

		sndlock->Lock();
		send_tasks.push(task);
		sndlock->Unlock();
		send->Set();
	}

	void ThreadMain() {
		uint8_t channelid;
		uint32_t iters;
		snd_task* task;
		while(true) {
			cout << "Starting to send" << endl;
			if(send_tasks.empty())
				send->Wait();
			cout << "Awoken" << endl;

			sndlock->Lock();
			iters = send_tasks.size();
			sndlock->Unlock();

			while(iters--) {
				task = send_tasks.front();
				send_tasks.pop();
				channelid = task->channelid;
				mysock->Send(&channelid, sizeof(uint8_t));
				mysock->Send(&task->bytelen, sizeof(uint64_t));
				mysock->Send(task->snd_buf, task->bytelen);

				cout << "Sending on channel " <<  (uint32_t) channelid << " a message of " << task->bytelen << " bytes length" << endl;

				free(task->snd_buf);
				free(task);

				if(channelid == ADMIN_CHANNEL)
					continue;
			}
		}
	}
	;
private:
	CLock* sndlock;
	CSocket* mysock;
	CEvent* send;
	std::queue<snd_task*> send_tasks;
};



class OTExt {

public:
	OTExt(){};
protected:
	void Init(uint32_t nSndVals, crypto* crypt, CSocket* sock, BYTE* keybytes, uint32_t nbaseOTs, uint32_t nbasekeys) {
		m_nSndVals = nSndVals;
		m_cCrypt = crypt;
		m_nSymSecParam = m_cCrypt->get_seclvl().symbits;
		m_nBaseOTs = nbaseOTs;
		m_nBlockSizeBits = pad_to_power_of_two(m_nBaseOTs);
		m_nBlockSizeBytes = pad_to_power_of_two(m_nBaseOTs/8);
		m_nCounter = 0;

		sndthread = new SndThread(sock);
		rcvthread = new RcvThread(sock);

		//sndthread->Start();
		//rcvthread->Start();

		m_vBaseOTKeys = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * nbasekeys);
		InitAESKey(m_vBaseOTKeys, keybytes, nbasekeys, m_cCrypt);

#ifdef FIXED_KEY_AES_HASHING
		m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		m_cCrypt->init_aes_key(m_kCRFKey, (uint8_t*) fixed_key_aes_seed);
#endif
	}

	void Cleanup() {
		delete sndthread;
		delete rcvthread;
		free(m_vBaseOTKeys);

	}

	eot_flavor m_eOTFlav;
	uint32_t m_nSndVals;
	uint64_t m_nOTs;
	uint64_t m_nBitLength;
	uint64_t m_nCounter;
	uint32_t m_nSymSecParam;
	uint32_t m_nBaseOTs;
	uint32_t m_nBlockSizeBits;
	uint32_t m_nBlockSizeBytes;

	crypto* m_cCrypt;

	SndThread* sndthread;
	RcvThread* rcvthread;

	AES_KEY_CTX* m_vBaseOTKeys;

	MaskingFunction* m_fMaskFct;

#ifdef FIXED_KEY_AES_HASHING
	AES_KEY_CTX* m_kCRFKey;
#endif
};




#ifdef FIXED_KEY_AES_HASHING
static const uint8_t fixed_key_aes_seed[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
#endif



#define OWF_BYTES AES_BYTES




#ifdef FIXED_KEY_AES_HASHING
inline void FixedKeyHashing(AES_KEY_CTX* aeskey, BYTE* outbuf, BYTE* inbuf, BYTE* tmpbuf, uint64_t id, uint32_t bytessecparam, crypto* crypt) {
#ifdef HIGH_SPEED_ROT_LT
	((uint64_t*) tmpbuf)[0] = id ^ ((uint64_t*) inbuf)[0];
	((uint64_t*) tmpbuf)[1] = ((uint64_t*) inbuf)[1];
#else
	memset(tmpbuf, 0, AES_BYTES);
	memcpy(tmpbuf, (BYTE*) (&id), sizeof(int));

	for (int i = 0; i < bytessecparam; i++) {
		tmpbuf[i] = tmpbuf[i] ^ inbuf[i];
	}
#endif

	crypt->encrypt(aeskey, outbuf, tmpbuf, AES_BYTES);

#ifdef HIGH_SPEED_ROT_LT
	((uint64_t*) outbuf)[0] ^= ((uint64_t*) inbuf)[0];
	((uint64_t*) outbuf)[1] ^= ((uint64_t*) inbuf)[1];
#else
	for (int i = 0; i < bytessecparam; i++) {
		outbuf[i] = outbuf[i] ^ inbuf[i];
	}
#endif
}
#endif



#endif /* __OT_EXTENSION_H_ */
