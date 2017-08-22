/*
 * carryless-multiplication.h
 *
 *  Created on: 18.08.2017
 *      Author: Matthias
 */

#ifndef OT_CARRYLESS_MULTIPLICATION_H_
#define OT_CARRYLESS_MULTIPLICATION_H_

#include "../ENCRYPTO_utils/typedefs.h"

// performs polynomial or carryless multiplication on a and b and XORs the result onto r.
// nBytes is the length of a and b which must be equal. r must hold at least 2*nBytes Bytes!
void carrylessMultiplication(uint8_t *a, uint8_t *b, uint8_t *r, uint32_t nBytes);


#endif /* OT_CARRYLESS_MULTIPLICATION_H_ */
