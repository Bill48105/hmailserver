// Copyright (c) 2008 Martin Knafve / hMailServer.com.  
// http://www.hmailserver.com

#include "stdafx.h"

#include "SMTPForwarding.h"
#include "SMTPConfiguration.h"
#include "RuleApplier.h"

#include "../Common/BO/Account.h"
#include "../Common/BO/MessageData.h"
#include "../Common/BO/Message.h"
#include "../Common/BO/MessageRecipients.h"

#include "../Common/Persistence/PersistentMessage.h"

#include "RecipientParser.h"

#ifdef _DEBUG
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif

namespace HM
{
   bool 
   SMTPForwarding::PerformForwarding(shared_ptr<const Account> pRecipientAccount, shared_ptr<Message> pOriginalMessage)
   //---------------------------------------------------------------------------()
   // DESCRIPTION:
   // Apply forwarding for the message.
   //---------------------------------------------------------------------------()
   {
      if (!pRecipientAccount->GetForwardEnabled())
         return true;
      
      if (pRecipientAccount->GetForwardAddress().IsEmpty())
      {
         // Configuration error. Forward was enabled, but no address specified.
         LOG_DEBUG(_T("SMTPDeliverer::_ApplyForwarding - Forward was enabled, but no address specified."));
         return true;
      }


      String sErrorMessage;
      bool bTreatSecurityAsLocal = false;
      RecipientParser recipientParser;

      String originalFileName = PersistentMessage::GetFileName(pRecipientAccount, pOriginalMessage);

      // Check that rule loop count is not yet reached.
      shared_ptr<MessageData> pOldMsgData  = shared_ptr<MessageData>(new MessageData());
      pOldMsgData->LoadFromMessage(originalFileName, pOriginalMessage);

      // false = check only loop counter not AutoSubmitted header because forward not rule
      if (!RuleApplier::IsGeneratedResponseAllowed(pOldMsgData, false))
      {
         ErrorManager::Instance()->ReportError(ErrorManager::Medium, 4333, "SMTPDeliverer::_ApplyForwarding", "Could not forward message. Maximum forward loop count reached.");

         return true;
      }

      LOG_DEBUG(_T("Forwarding message"));

      // Create a copy of the message
      shared_ptr<Message> pNewMessage = PersistentMessage::CopyToQueue(pRecipientAccount, pOriginalMessage);
     
      pNewMessage->SetState(Message::Delivering);
      
      // Increase the number of rule-deliveries made.
      shared_ptr<MessageData> pNewMsgData = shared_ptr<MessageData>(new MessageData());
      const String newFileName = PersistentMessage::GetFileName(pNewMessage);
      pNewMsgData->LoadFromMessage(newFileName, pNewMessage);
      pNewMsgData->IncreaseRuleLoopCount();
      pNewMsgData->Write(newFileName);


      // Add new recipients
      bool recipientOK = false;
      AnsiString sRecipientAcct = pRecipientAccount->GetAddress();

      AnsiString sForwardAddress = pRecipientAccount->GetForwardAddress();

      // Look for multi address separated by commas
      vector<AnsiString> vforwardaddresses = StringParser::SplitString(sForwardAddress,",");
      boost_foreach(AnsiString oneforwardaddress, vforwardaddresses)
      {

         LOG_DEBUG(_T("SMTPDeliverer::_ApplyForwarding - Multiforward address found: " + oneforwardaddress));

         if (_stricmp(oneforwardaddress, sRecipientAcct) != 0)
         {

            // returned value doesn't appear to be used but resetting to false anyway just in case
            bTreatSecurityAsLocal = false;

            recipientOK = false;
            recipientParser.CreateMessageRecipientList(oneforwardaddress, pNewMessage->GetRecipients(), recipientOK);

             if (recipientOK) LOG_DEBUG(_T("SMTPDeliverer::_ApplyForwarding - recipientOK")) else LOG_DEBUG(_T("SMTPDeliverer::_ApplyForwarding - recipient!OK"));

         }
         else
         {
            ErrorManager::Instance()->ReportError(ErrorManager::Medium, 4334, "SMTPDeliverer::_ApplyForwarding", "Could not forward message to recipient since target address same as account address.");
         }
      }

      // Check that there are recipients of the letter. If not, we should skip delivery.
      if (pNewMessage->GetRecipients()->GetCount() == 0)
      {
         // Delete the file since the message cannot be delivered.
         FileUtilities::DeleteFile(newFileName);
         
         ErrorManager::Instance()->ReportError(ErrorManager::Medium, 4332, "SMTPDeliverer::_ApplyForwarding", "Could not forward message; no recipients.");

         return true;
      }

      PersistentMessage::SaveObject(pNewMessage);

      bool bKeepOriginal = pRecipientAccount->GetForwardKeepOriginal();

      return bKeepOriginal;
   }

}

