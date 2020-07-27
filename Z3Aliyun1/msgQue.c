/*
 * msgQue.c
 *
 *  Created on: Jul 20, 2020
 *      Author: root
 */
#include "app/framework/include/af.h"
#include "dbgprint.h"
#include "msgQue.h"

AppMsgHdr g_appMsgBuffer[MSG_BUFFER_MAX_NUM] = {0};

void msgq_InitBuffer()
{
	for (int i = 0; i < MSG_BUFFER_MAX_NUM; i++) {
		g_appMsgBuffer[i].msgCmd = 0xFF;  //Use 0xFF
	}
}

AppMsgHdr *msgq_AllocBuffer()
{
	AppMsgHdr *pMsg = NULL;

	CORE_ATOMIC_SECTION(
		for (int i = 0; i < MSG_BUFFER_MAX_NUM; i++) {
			if (0xFF == g_appMsgBuffer[i].msgCmd) {
				g_appMsgBuffer[i].msgCmd = 0xFE;
				pMsg = &g_appMsgBuffer[i];
				break;
			}
		}
	)

	return pMsg;
}

void msgq_FreeBuffer(AppMsgHdr *pBuffer)
{
	CORE_ATOMIC_SECTION(
		pBuffer->msgCmd = 0xFF;
	)
}

int msgq_CreateMsgQ(OS_Q *pQue, char *pName, uint8_t size)
{
	RTOS_ERR err;
	OSQCreate((OS_Q     *)pQue,
			  (CPU_CHAR *)pName,
			  (OS_MSG_QTY)size,
			  (RTOS_ERR *)&err);
	APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
	return 0;
}

AppMsgHdr *msgq_DeQueue(OS_Q *pQue)
{
	RTOS_ERR 		err;
	OS_MSG_SIZE 	msgSize;
	AppMsgHdr 	   *pMsg = NULL;

	pMsg = (AppMsgHdr *)OSQPend((OS_Q*       )pQue,
							    (OS_TICK     )0,
							    (OS_OPT      )OS_OPT_PEND_NON_BLOCKING,
							    (OS_MSG_SIZE*)&msgSize,
							    (CPU_TS*     )DEF_NULL,
							    (RTOS_ERR*   )&err);
//	APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
	if (RTOS_ERR_NONE != RTOS_ERR_CODE_GET(err)) {
		pMsg = NULL;
	}
	return pMsg;
}

void msgq_EnQueue(OS_Q *pQue, AppMsgHdr *pMsg)
{
	RTOS_ERR err;

	while (1) {
		OSQPost((OS_Q*      )pQue,
				(void*      )pMsg,
				(OS_MSG_SIZE) (sizeof(AppMsgHdr)),
				(OS_OPT     ) OS_OPT_POST_FIFO,
				(RTOS_ERR*  ) &err);
		if (RTOS_ERR_NONE == RTOS_ERR_CODE_GET(err)) {
			break;
		}

		OSTimeDly(1, OS_OPT_TIME_DLY, &err);
	}

	return;
}
