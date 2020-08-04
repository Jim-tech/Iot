/*
 * dbgprint.h
 *
 *  Created on: Jul 20, 2020
 *      Author: root
 */

#ifndef DBGPRINT_H_
#define DBGPRINT_H_

#include "stdio.h"
#include "stdlib.h"

//#define DEBUG 1

#define dbg_print(...) printf("[%s][%d]", __func__, __LINE__);printf(__VA_ARGS__);printf("\r\n");

#ifdef DEBUG
#define dbg_trace(...) inner_print("[%s][%d]", __func__, __LINE__);inner_print(__VA_ARGS__);inner_print("\r\n");
#define dbg_dump(...)  inner_print(__VA_ARGS__)
#else
#define dbg_trace(...)
#define dbg_dump(...)
#endif
#define dbg_error(...) printf("\033[31m[%s][%d]", __func__, __LINE__);printf(__VA_ARGS__);printf("\r\n");printf("\33[37m");

#endif /* DBGPRINT_H_ */
