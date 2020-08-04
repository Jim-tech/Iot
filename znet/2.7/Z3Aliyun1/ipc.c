/*
 * ipc.c
 *
 *  Created on: Jul 20, 2020
 *      Author: root
 */
#include "app/framework/include/af.h"
#include "dbgprint.h"
#include "msgQue.h"
#include "ipc.h"

int ipc_SendZigbeeCmdCommon(uint8_t cmd, void *pPara, uint8_t paraSize)
{
	AppMsgHdr 	   *pMsg = NULL;

	pMsg = msgq_AllocBuffer();
	if (NULL == pMsg) {
		dbg_error("not enough msg buffer, cmd=%x", cmd);
		return -1;
	}

	pMsg->msgCmd = cmd;
	if (NULL != pPara && 0 != paraSize) {
		pMsg->dataLen = paraSize;
		memcpy(pMsg->data, pPara, paraSize);
	} else {
		pMsg->dataLen = 0;
	}
	msgq_EnQueue(&ZBMsgQueue, pMsg);
	return 0;
}

int ipc_SendAliyunCmdCommon(uint8_t cmd, void *pPara, uint8_t paraSize)
{
	AppMsgHdr 	   *pMsg = NULL;

	pMsg = msgq_AllocBuffer();
	if (NULL == pMsg) {
		dbg_error("not enough msg buffer, cmd=%x", cmd);
		return -1;
	}

	pMsg->msgCmd = cmd;
	if (NULL != pPara && 0 != paraSize) {
		pMsg->dataLen = paraSize;
		memcpy(pMsg->data, pPara, paraSize);
	} else {
		pMsg->dataLen = 0;
	}
	msgq_EnQueue(&AliyunMsgQueue, pMsg);
	return 0;
}
