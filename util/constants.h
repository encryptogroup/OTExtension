/**
 \file 		constants.h
 \author	michael.zohner@ec-spride.de
 \copyright	________________
 \brief		File containing all constants used throughout the source
 */

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include "typedefs.h"

//Defines for parameterizing the OT extension
//#define DEBUG
//#define FIXED_KEY_AES_HASHING
//#define AES_OWF
#define VERIFY_OT
//#define OT_HASH_DEBUG
#define OTTiming
//#define HIGH_SPEED_ROT_LT



#define AES_KEY_BITS			128
#define AES_KEY_BYTES			16
#define AES_BITS				128
#define AES_BYTES				16
#define LOG2_AES_BITS			ceil_log2(AES_BITS)

const BYTE G_OT = 0x01;
const BYTE C_OT = 0x02;
const BYTE R_OT = 0x03;

#define NUMOTBLOCKS 128

enum field_type {
	P_FIELD, ECC_FIELD
};

static const seclvl ST = { 40, 80, 1024, 160, 163 };
static const seclvl MT = { 40, 112, 2048, 192, 233 };
static const seclvl LT = { 40, 128, 3072, 256, 283 };
static const seclvl XLT = { 40, 192, 7680, 384, 409 };
static const seclvl XXLT = { 40, 256, 15360, 512, 571 };

const uint8_t m_vFixedKeyAESSeed[AES_KEY_BYTES] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
/** \var m_vSeed
 \brief Static seed for various testing functionalities
 */
const uint8_t m_vSeed[AES_KEY_BYTES] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

#endif /* CONSTANTS_H_ */
