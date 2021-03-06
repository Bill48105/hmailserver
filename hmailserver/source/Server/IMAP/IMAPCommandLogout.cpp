// Copyright (c) 2010 Martin Knafve / hMailServer.com.  
// http://www.hmailserver.com

#include "stdafx.h"
#include "IMAPCommandLogout.h"
#include "IMAPConnection.h"
#include "../Common/BO/IMAPFolders.h"
#include "../Common/BO/IMAPFolder.h"
#include "../Common/BO/Messages.h"

#ifdef _DEBUG
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif

namespace HM
{
   IMAPResult
   IMAPCommandLOGOUT::ExecuteCommand(shared_ptr<IMAPConnection> pConnection, shared_ptr<IMAPCommandArgument> pArgument)
   {
      String sResponse = "* BYE Have a nice day\r\n"; 
      sResponse += pArgument->Tag() + " OK Logout completed\r\n";

      pConnection->Logout(sResponse);

      return IMAPResult();
   }
}