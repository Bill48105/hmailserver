// Copyright (c) 2010 Martin Knafve / hMailServer.com.  
// http://www.hmailserver.com

#include "StdAfx.h"
#include "TCPConnection.h"

#include "ProtocolParser.h"
#include "../Util/ByteBuffer.h"

#include "../BO/TCPIPPorts.h"
#include "../TCPIP/LocalIPAddresses.h"
#include "../TCPIP/IPAddress.h"

#include "../Persistence/PersistentSecurityRange.h"

#include "IOOperation.h"

#ifdef _DEBUG
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif

namespace HM
{
  

   TCPConnection::TCPConnection(bool useSSL,
                                boost::asio::io_service& io_service, 
                                boost::asio::ssl::context& context,
                                int stateSTARTTLS) :
      _useSSL(useSSL),
      _socket(io_service),
      _sslSocket(io_service, context),
      _resolver(io_service),
      _timer(io_service),
      _receiveBinary(false),
      _remotePort(0),
      _hasTimeout(false),
      _receiveBuffer(250000),
      _stateSTARTTLS(stateSTARTTLS)

   {
      _handshakeDone = false;
   }

   TCPConnection::~TCPConnection(void)
   {
      try
      {
         _connectionTermination.Set(); 
      }
      catch (...)
      {
         ReportError(ErrorManager::Low, 5139, "TCPConnection::~TCPConnection", "An error occurred while setting connection termination flag.");
         throw;
      }

      CancelLogoutTimer();
   }

   ssl_socket::lowest_layer_type& 
   TCPConnection::GetSocket()
   {
      if (_useSSL)
if ((_stateSTARTTLS == 1) || (_stateSTARTTLS == 2))
{

if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG("TCPCconnection::GetSocket(): next_layer()");
			  return _sslSocket.next_layer();
		  } else {
if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG("TCPCconnection::GetSocket(): lowest_layer()");
			  return _sslSocket.lowest_layer();
		  }
      else
         return _socket;
   }

   bool
   TCPConnection::Connect(const AnsiString &remoteServer, long remotePort, const IPAddress &localAddress)
   {
      try
      {
         LOG_TCPIP("Connecting to " + remoteServer + "...");

         _remotePort = remotePort;
         _remoteServer = remoteServer;

         if (!localAddress.IsAny())
         {

            try
            {
               if (localAddress.GetType() == IPAddress::IPV4)
                  GetSocket().open(boost::asio::ip::tcp::v4());
               else if (localAddress.GetType() == IPAddress::IPV6)
                  GetSocket().open(boost::asio::ip::tcp::v6());
               GetSocket().bind(boost::asio::ip::tcp::endpoint(localAddress.GetAddress(), 0));
            }
            catch (boost::system::system_error error)
            {
               try
               {
                  // this may throw...
                  GetSocket().close();
               }
               catch (...)
               {
                  // shouldn't be an error.
               }


               String errorMessage = Formatter::Format("Failed to bind to IP address {0}.", localAddress.ToString());
               ReportError(ErrorManager::Medium, 4330, "TCPConnection::Connect", errorMessage, error);

               return false;
            }
         }

   #ifdef _DEBUG
         String sMessage;
         sMessage.Format(_T("RESOLVE: %s\r\n"), String(remoteServer));
   #endif 

         // Start an asynchronous resolve to translate the server and service names
         // into a list of endpoints.
         AnsiString sPort = StringParser::IntToString(remotePort);
         
         boost::asio::ip::resolver_query_base::flags flags;

         if (StringParser::IsValidIPAddress(remoteServer))
         {
            flags = tcp::resolver::query::passive |
                    tcp::resolver::query::numeric_host |
                     tcp::resolver::query::numeric_service;
         }
         else
         {
            flags =  
               tcp::resolver::query::passive |
               tcp::resolver::query::numeric_service;
         }


         tcp::resolver::query query(remoteServer, sPort, flags);

         _resolver.async_resolve(query,
            boost::bind(&TCPConnection::HandleResolve, shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::iterator));

         return true;
      }
      catch (...)
      {
         String errorMessage = Formatter::Format("An unknown error occurred while connecting to {0} on port {1}", remoteServer, remotePort);
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5321, "TCPConnection::Connect", errorMessage);
         throw;
      }
   }

   void 
   TCPConnection::HandleResolve(const boost::system::error_code& err, tcp::resolver::iterator endpoint_iterator)
   {
      try
      {
         if (err)
         {
            AnsiString error = err.message();
            if (_protocolParser)
               _protocolParser->OnCouldNotConnect("Host name: " + _remoteServer + ", message: " + error);
            return;
         }

         _StartAsyncConnect(endpoint_iterator);
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5322, "TCPConnection::Connect", "An unknown error occurred while handling TCP/IP resolve.");
         throw;
      }
   }

   void
   TCPConnection::_StartAsyncConnect(tcp::resolver::iterator endpoint_iterator)
   {
      try
      {
         // Check that we don't try to connect to a port we're listening on. Doing
         // that could start evil loops.
         tcp::endpoint endpoint = *endpoint_iterator;

         if (LocalIPAddresses::Instance()->IsLocalPort(endpoint.address(), _remotePort))
         {
            String sMessage; 
            sMessage.Format(_T("Could not connect to %s on port %d since this would mean connecting to myself."), _remoteServer, _remotePort);

            if (_protocolParser)
               _protocolParser->OnCouldNotConnect(sMessage);

            LOG_TCPIP(_T("TCPConnection - ") + sMessage);

            return;
         }

         // Attempt a connection to the first endpoint in the list. Each endpoint
         // will be tried until we successfully establish a connection.
         try
         {
            GetSocket().async_connect(endpoint,
               boost::bind(&TCPConnection::HandleConnect, shared_from_this(),
               boost::asio::placeholders::error, ++endpoint_iterator));
         }
         catch (boost::system::system_error error)
         {
            // We failed to send the data to the client. Log an message in the log, 
            // and switch of operation-in-progress flag. We don't log this as an 
            // error since it most likely isn't.
            String sMessage;
            sMessage.Format(_T("TCPConnection - Call to async_connect failed. Error code: %d, Message: %s"), error.code().value(), String(error.what()));
            LOG_TCPIP(sMessage);
         }
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5323, "TCPConnection::_StartAsyncConnect", "An unknown error occurred while starting asynchronous connect.");
         throw;
      }
   }

   void
   TCPConnection::HandleConnect(const boost::system::error_code& err, tcp::resolver::iterator endpoint_iterator)
   {
      try
      {
         if (err)
         {
            // Are there more addresses we should attempt to connect to?
            if (endpoint_iterator != tcp::resolver::iterator())
            {
               GetSocket().close();

               // Attemp with the next address.
               _StartAsyncConnect(endpoint_iterator);
               
               return;
            }
            
            AnsiString error = err.message();

            if (_protocolParser)
               _protocolParser->OnCouldNotConnect("Host name: " + _remoteServer + ", message: " + error);

            return;
         }

         if (_useSSL)
         {

// temp hack to try starttls
if (_stateSTARTTLS > 0)
{

if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::~TCPConnection 4USESSL & TLS1");


            // Send welcome message to client.
            _protocolParser->OnConnected();

}
else
{
if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG("TCPConnection::~TCPConnection 5USESSL & TLS!1");


            boost::asio::ssl::stream_base::handshake_type handshakeType = IsClient() ?
               boost::asio::ssl::stream_base::client :
               boost::asio::ssl::stream_base::server;
               
            _sslSocket.async_handshake(handshakeType,
               boost::bind(&TCPConnection::HandleHandshake, shared_from_this(),
               boost::asio::placeholders::error));
}

         }
         else
         {
if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::~TCPConnection 6!USESSL & !TLS");
            // Send welcome message to client.
            _protocolParser->OnConnected();
         }
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5324, "TCPConnection::HandleConnect", "An unknown error occurred while handling asynchronous connect.");
         throw;
      }
   }
   
   void 
   TCPConnection::Start(shared_ptr<ProtocolParser> protocolParser)
   {
      try
      {
         _protocolParser = protocolParser;
         _protocolParser->Initialize(this);

         if (_useSSL)
         {
            try
            {
               if (GetSocket().is_open())
               {

if ((_stateSTARTTLS == 1))
{
if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::~TCPConnection _stateSTARTTLS 1");

               // Send welcome message to client.
               _protocolParser->OnConnected();

}
else
{

if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::~TCPConnection _stateSTARTTLS 0/2/3");
      
                  _sslSocket.async_handshake(boost::asio::ssl::stream_base::server,
                     boost::bind(&TCPConnection::HandleHandshake, shared_from_this(),
                     boost::asio::placeholders::error));
}

               }
            }
            catch (boost::system::system_error error)
            {
               String sMessage;
               sMessage.Format(_T("TCPConnection - Call to async_handshake failed. Error code: %d, Message: %s"), error.code().value(), String(error.what()));
               LOG_TCPIP(sMessage);
            }
         }
         else
         {
            if (GetSocket().is_open())
            {
               // Send welcome message to client.
               _protocolParser->OnConnected();
            }
         }
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5325, "TCPConnection::Start", "An unknown error occurred while starting connection.");
         throw;
      }
   }

   void 
   TCPConnection::HandleHandshake(const boost::system::error_code& error)
   {
      try
      {
         if (!error)
         {

            if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::HandleHandshake Completed");

            bool _StartTLSEnabled = (_stateSTARTTLS == 2);
            _handshakeDone = true;
            _stateSTARTTLS=3;			 

            // Send welcome message to client.
            if (_StartTLSEnabled)
            {
               _protocolParser->PostReceive(); 
            }
            else
            {
               _protocolParser->OnConnected();
            }
         }
         else
         {
            // The SSL handshake failed. This may happen for example if the user who has connected
            // to the TCP/IP port disconnects immediately without sending any data.
            String sMessage;
            sMessage.Format(_T("TCPConnection - SSL handshake with client failed. Error code: %d, Message: %s, Remote IP: %s"), error.value(), String(error.message()), SafeGetIPAddress());
            LOG_TCPIP(sMessage);

         }
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5326, "TCPConnection::HandleHandshake", "An unknown error occurred while handling handshake.");
         throw;
      }

   }

   void 
   TCPConnection::PostWrite(const AnsiString &sData)
   {
      // Test fix for IOCP crashes
      CriticalSectionScope scope (_criticalSection);
      
      try
      {
         AnsiString sTemp = sData;
         char *pBuf = sTemp.GetBuffer();
         
         shared_ptr<ByteBuffer> pBuffer = shared_ptr<ByteBuffer>(new ByteBuffer());
         pBuffer->Add((BYTE*) pBuf, sData.GetLength());
         
   #ifdef _DEBUG
         String sDebugOutput;
         sDebugOutput.Format(_T("SENT: %s"), String(sTemp));
         OutputDebugString(sDebugOutput);
   #endif

         PostWrite(pBuffer);
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5327, "TCPConnection::PostWrite", "An unknown error occurred while posting write buffer.");
         throw;
      }

   }

   void 
   TCPConnection::PostWrite(shared_ptr<ByteBuffer> pBuffer)
   {

      // Test fix for IOCP crashes
      CriticalSectionScope scope (_criticalSection);
      
      try
      {
         shared_ptr<IOOperation> operation = shared_ptr<IOOperation>(new IOOperation(IOOperation::BCTSend, pBuffer));
         _operationQueue.Push(operation);

         _ProcessOperationQueue();
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5328, "TCPConnection::PostWrite", "An unknown error occurred while posting write buffer.");
         throw;
      }
   }

   void
   TCPConnection::_ProcessOperationQueue()
   {

	  if ((_stateSTARTTLS == 2) && (_handshakeDone == false)) return;

      int stage = 0;

      try
      {
         stage = 1;
         // Pick out the next item to process...
         shared_ptr<IOOperation> operation = _operationQueue.Front();

         stage = 2;
         if (!operation)
         {
            // We're no longer sending...
            stage = 20;
            return;
         }
         stage = 3;

        switch (operation->GetType())
         {
         case IOOperation::BCTSend:
            {
               stage = 4;
               shared_ptr<ByteBuffer> pBuf = operation->GetBuffer();
               Write(pBuf);
               stage = 5;
               break;
            }
         case IOOperation::BCTReceive:
            {
               stage = 6;
               Read(operation->GetString());               
               stage = 7;
               break;
            }
         case IOOperation::BCTShutdownSend:
            {
               stage = 8;
               Shutdown(boost::asio::ip::tcp::socket::shutdown_send, true);
               stage = 9;
               _ProcessOperationQueue();
               stage = 10;

               break;
            }
         case IOOperation::BCTDisconnect:
            {
               stage = 11;
               Disconnect();
               stage = 12;
               break;
            }
         }
      }
      catch (boost::system::system_error error)
      {
         ReportError(ErrorManager::Medium, 5138, "TCPConnection::_ProcessOperationQueue", 
            Formatter::Format("An error occured while processing the queue. Stage: {0}", stage), error);
      }
      catch (...)
      {
         ReportError(ErrorManager::Medium, 5138, "TCPConnection::_ProcessOperationQueue", 
            Formatter::Format("An error occured while processing the queue. Stage: {0}", stage));
      }
   }

   void 
   TCPConnection::ReportError(ErrorManager::eSeverity sev, int code, const String &context, const String &message, const boost::system::system_error &error)
   {
      String formattedMessage;
      formattedMessage.Format(_T("%s Remote IP: %s, Error code: %d, Message: %s"), message, SafeGetIPAddress(), error.code().value(), String(error.what()));
      ErrorManager::Instance()->ReportError(sev, code, context, formattedMessage);         
   }

   void 
   TCPConnection::ReportError(ErrorManager::eSeverity sev, int code, const String &context, const String &message)
   {
      String formattedMessage;
      formattedMessage.Format(_T("%s Remote IP: %s"), message, SafeGetIPAddress());
      ErrorManager::Instance()->ReportError(sev, code, context, formattedMessage);         
   }

   void 
   TCPConnection::ReportInitError(ErrorManager::eSeverity sev, int code, const String &context, const String &message, const boost::system::system_error &error)
   {
      String formattedMessage;
      formattedMessage.Format(_T("%s, Error code: %d, Message: %s"), message, error.code().value(), String(error.what()));
      ErrorManager::Instance()->ReportError(sev, code, context, formattedMessage);         
   }

   void 
   TCPConnection::ReportDebugMessage(const String &message, const boost::system::error_code &error)
   {
      String formattedMessage;
      formattedMessage.Format(_T("%s Remote IP: %s, Session: %d, Code: %d, Message: %s"), message, SafeGetIPAddress(), GetSessionID(), error.value(), String(error.message()));

      LOG_DEBUG(formattedMessage);
   }

   void 
   TCPConnection::Write(shared_ptr<ByteBuffer> buffer)
   {
      // Test fix for IOCP crashes
      CriticalSectionScope scope (_criticalSection);
      try
      {
         int timeout = _protocolParser->GetTimeout();

         function<void (const boost::system::error_code&, size_t)> handleWriteFunction =
            boost::bind(&TCPConnection::HandleWrite, shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred);

         try
         {
            if (_useSSL)
            {
               if ((_stateSTARTTLS == 1) || (_stateSTARTTLS == 2))
               {
                  if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::Write next_layer()");
                  boost::asio::async_write
                  (_sslSocket.next_layer(), boost::asio::buffer(buffer->GetCharBuffer(), buffer->GetSize()), handleWriteFunction);
            }
            else
            {
               if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::Write ssl");
               boost::asio::async_write
               (_sslSocket, boost::asio::buffer(buffer->GetCharBuffer(), buffer->GetSize()), handleWriteFunction);
            }
         }
         else
         {
            if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::Write non ssl");
               boost::asio::async_write
                  (_socket, boost::asio::buffer(buffer->GetCharBuffer(), buffer->GetSize()), handleWriteFunction);
         }

            UpdateLogoutTimer();
         }
         catch (boost::system::system_error error)
         {
            // We failed to send the data to the client. Log an message in the log, 
            // and switch of operation-in-progress flag. We don't log this as an 
            // error since it most likely isn't.
            String sMessage;
            sMessage.Format(_T("TCPConnection - Sending of data to client failed. Error code: %d, Message: %s, Remote IP: %s"), error.code().value(), String(error.what()), SafeGetIPAddress());
            LOG_TCPIP(sMessage);
         }
         catch (std::exception const& e)
         {
            String sErrorMessage = Formatter::Format("Write operation failed. Error: {0}", e.what());
            ErrorManager::Instance()->ReportError(ErrorManager::High, 4208, "Temp::Temp", sErrorMessage);
         }
         catch (...)
         {
            ErrorManager::Instance()->ReportError(ErrorManager::High, 5000, "Temp::Temp", "Write operation failed.");
            throw;
         }
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5329, "TCPConnection::Write", "An unknown error occurred while writing buffer.");
         throw;
      }

   }

   void 
   TCPConnection::Shutdown(boost::asio::socket_base::shutdown_type what, bool removeFromQueue)
   {
      try
      {
         // Remove the item we have just handled.
         if (removeFromQueue)
            _operationQueue.Pop(IOOperation::BCTShutdownSend);

         try
         {
            GetSocket().shutdown(what);
         }
         catch (boost::system::system_error)
         {
            // hopefully should not matter.
         }


         _ProcessOperationQueue();
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5330, "TCPConnection::Shutdown", "An unknown error occurred while shutting down socket.");
         throw;
      }

   }

   void 
   TCPConnection::PostRead(const AnsiString &delimitor)
   {

      // Test fix for IOCP crashes
      CriticalSectionScope scope (_criticalSection);
      
      try
      {
         shared_ptr<IOOperation> operation = shared_ptr<IOOperation>(new IOOperation(IOOperation::BCTReceive, delimitor));
         _operationQueue.Push(operation);

         _ProcessOperationQueue();
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5331, "TCPConnection::PostRead", "An unknown error occurred while posting read buffer.");
         throw;
      }
   }

   void 
   TCPConnection::Read(const AnsiString &delimitor)
   {

      // Test fix for IOCP crashes
      CriticalSectionScope scope (_criticalSection);

      try
      {
         function<void (const boost::system::error_code&, size_t)> handleReadFunction =
            boost::bind(&TCPConnection::HandleRead, shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred);

         try
         {
            if (_useSSL)
            {
               if ((_stateSTARTTLS == 1)||(_stateSTARTTLS == 2))
               {
                  if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::Read next_layer()");
                  if (delimitor.GetLength() == 0)
                     boost::asio::async_read(_sslSocket.next_layer(), _receiveBuffer, boost::asio::transfer_at_least(1), handleReadFunction);
               else
                  boost::asio::async_read_until(_sslSocket.next_layer(), _receiveBuffer,  delimitor, handleReadFunction);

            }
            else
            {
               if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::Read ssl");
               if (delimitor.GetLength() == 0)
                  boost::asio::async_read(_sslSocket, _receiveBuffer, boost::asio::transfer_at_least(1), handleReadFunction);
               else
                  boost::asio::async_read_until(_sslSocket, _receiveBuffer,  delimitor, handleReadFunction);
            }

            }
            else
            {

               if (IniFileSettings::Instance()->GetLogLevel() > 99) LOG_DEBUG("TCPConnection::Read non ssl");

               if (delimitor.GetLength() == 0)
                  boost::asio::async_read(_socket, _receiveBuffer, boost::asio::transfer_at_least(1), handleReadFunction);
               else
                  boost::asio::async_read_until(_socket, _receiveBuffer, delimitor, handleReadFunction);
            }

            UpdateLogoutTimer();
         }
         catch (boost::system::system_error error)
         {
            // We failed to send the data to the client. Log an message in the log, 
            // and switch of operation-in-progress flag. We don't log this as an 
            // error since it most likely isn't.
            String sMessage;
            sMessage.Format(_T("TCPConnection - Receiving of data from client failed. Error code: %d, Message: %s, Remote IP: %s"), error.code().value(), String(error.what()), SafeGetIPAddress());
            LOG_TCPIP(sMessage);
         }
         catch (std::exception const& e)
         {
            String sErrorMessage = Formatter::Format("Read operation failed. Error: {0}", e.what());
            ErrorManager::Instance()->ReportError(ErrorManager::High, 4208, "Temp::Temp", sErrorMessage);
         }
         catch (...)
         {
            ErrorManager::Instance()->ReportError(ErrorManager::High, 5000, "Temp::Temp", "Read operation failed.");
            throw;
         }
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5332, "TCPConnection::Read", "An unknown error occurred while starting async reading.");
         throw;
      }
   }

   void 
   TCPConnection::UpdateLogoutTimer()
   {
      try
      {
         // Put a timeout...
         int timeout = _protocolParser->GetTimeout();
         _timer.expires_from_now(boost::posix_time::seconds(timeout));
         _timer.async_wait(bind(&TCPConnection::OnTimeout, 
            boost::weak_ptr<TCPConnection>(shared_from_this()), _1));
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5333, "TCPConnection::UpdateLogoutTimer", "An unknown error occurred while updating logout timer.");
         throw;
      }
   }

   void 
   TCPConnection::CancelLogoutTimer()
   {
      try
      {
         _timer.cancel();
      }
      catch (boost::system::system_error error)
      {
         ReportError(ErrorManager::Low, 5211, "TCPConnection::CancelLogoutTimer", "Failed to logout timer", error);
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5334, "TCPConnection::CancelLogoutTimer", "An unknown error occurred while canceling logout timer.");
         throw;
      }
      
   }

   void 
   TCPConnection::PostDisconnect()
   {
      try
      {
         shared_ptr<ByteBuffer> pBuf;
         shared_ptr<IOOperation> operation = shared_ptr<IOOperation>(new IOOperation(IOOperation::BCTDisconnect, pBuf));
         _operationQueue.Push(operation);

         _ProcessOperationQueue();
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5335, "TCPConnection::PostDisconnect", "An unknown error occurred while posting disconnect.");
         throw;
      }
   }

   void 
   TCPConnection::Disconnect()
   {
      try
      {
         LOG_DEBUG("Closing TCP/IP socket");

         Shutdown(boost::asio::socket_base::shutdown_both, false);

         try
         {
            GetSocket().close();
         }
         catch (boost::system::system_error error)
         {
            // We failed to send the data to the client. Log an message in the log, 
            // and switch of operation-in-progress flag. We don't log this as an 
            // error since it most likely isn't.
            String sMessage;
            sMessage.Format(_T("TCPConnection - Closing of socket failed. Error code: %d, Message: %s"), error.code().value(), String(error.what()));
            LOG_TCPIP(sMessage);
         }
         catch (...)
         {
            LOG_DEBUG("GetSocket().close() threw");
            // Eat the exception. Not immediately critical.
         }
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5336, "TCPConnection::Disconnect", "An unknown error occurred while disconnecting.");
         throw;
      }

   }

   void
   TCPConnection::OnTimeout(boost::weak_ptr<TCPConnection> connection, boost::system::error_code const& err)
   {
      try
      {
         boost::shared_ptr<TCPConnection> conn = connection.lock();
         if (!conn)
         {
            return;
         }

         if (err == asio::error::operation_aborted) 
         {
            // the timeout operation was cancelled.
            return;
         }

         String message;
         message.Format(_T("The client has timed out. Session: %d"), conn->GetSessionID());
         LOG_DEBUG(message);

         conn->PostTimeout();
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5337, "TCPConnection::OnTimeout", "An unknown error occurred while handling timeout.");
         throw;
      }
   }

   void 
   TCPConnection::PostTimeout()
   {
      try
      {
         if (_hasTimeout)
         {
            // We've already posted a timeout once. Disconnect now.
            Disconnect();
            return;
         }

         _hasTimeout = true;

         _protocolParser->OnConnectionTimeout();

         PostDisconnect();
      }
      catch (boost::system::system_error error)
      {
         ReportError(ErrorManager::Low, 5137, "TCPConnection::PostTimeout", "An error occured while sending a timeout message to the client.", error);
      }
      catch (...)
      {
         ReportError(ErrorManager::Low, 5137, "TCPConnection::PostTimeout", "An error occured while sending a timeout message to the client.");
      }
   }

   void 
   TCPConnection::PostShutdown(ShutdownOption what)
   {
      try
      {
         switch (what)
         {
         case TCPConnection::ShutdownSend:
            {
               shared_ptr<ByteBuffer> pBuf;
               shared_ptr<IOOperation> operation = shared_ptr<IOOperation>(new IOOperation(IOOperation::BCTShutdownSend, pBuf));
               _operationQueue.Push(operation);

               _ProcessOperationQueue();
            }
            
           break;
         }
      }
      catch (...)
      {
         ErrorManager::Instance()->ReportError(ErrorManager::High, 5338, "TCPConnection::PostShutdown", "An unknown error occurred while posting shutdown.");
         throw;
      }
   }

   void 
   TCPConnection::HandleRead(const boost::system::error_code& error,  size_t bytes_transferred)
   {

            // Test fix for IOCP crashes
            CriticalSectionScope scope (_criticalSection);
      
      try
      {
         // Remove the item we have just handled.
         try
         {
            _operationQueue.Pop(IOOperation::BCTReceive);
         }
         catch (...)
         {
            ReportError(ErrorManager::Medium, 5141, "TCPConnection::HandleRead", "An error occurred while popping queue");
            throw;
         }

         try
         {
            if (error.value() != 0)
            {
               // This isn't really an error.
               bool isClientDisconnectedError = error.value() == 2;
               
               if (isClientDisconnectedError == false)
               {
                  _protocolParser->OnReadError(error.value());

                  String message;
                  message.Format(_T("The read operation failed. Bytes transferred: %d"), bytes_transferred);
                  ReportDebugMessage(message, error);
               }

               if (error.value() == boost::asio::error::not_found)
               {
                  // read buffer is full...
                  _protocolParser->OnExcessiveDataReceived();
                  PostDisconnect();
                  return;
               }

               return;
            }
         }
         catch (...)
         {
            ReportError(ErrorManager::Medium, 5141, "TCPConnection::HandleRead", "An error occurred while checking error state");
            throw;
         }

         // Disable the logout timer while we're parsing data. We don't want to terminate
         // a client just because he has issued a long-running command. If we do this, we
         // would have to take care of the fact that we're dropping a connectio despite it
         // still being active.
         try
         {
            CancelLogoutTimer();
         }
         catch (...)
         {
            ReportError(ErrorManager::Medium, 5141, "TCPConnection::HandleRead", "An error occurred while cancelling logout timer.");
            throw;
         }

         if (_receiveBinary)
         {
            try
            {
               shared_ptr<ByteBuffer> pBuffer = shared_ptr<ByteBuffer>(new ByteBuffer());
               pBuffer->Allocate(_receiveBuffer.size());

               std::istream is(&_receiveBuffer);
               is.read((char*) pBuffer->GetBuffer(), _receiveBuffer.size());

               try
               {
                  _protocolParser->ParseData(pBuffer);
               }
               catch (boost::system::system_error error)
               {
                  ReportError(ErrorManager::Medium, 5136, "TCPConnection::HandleRead", "An error occured while parsing buffer.", error);
                  throw;
               }
               catch (...)
               {
                  String message;
                  message.Format(_T("An error occured while parsing buffer. Received bytes: %d, Buffer: %d, Buffer size: %d"), bytes_transferred, &pBuffer, pBuffer->GetSize());

                  ReportError(ErrorManager::Medium, 5136, "TCPConnection::HandleRead", "An error occured while parsing buffer.");
                  throw;
               }
            }
            catch (...)
            {
               ReportError(ErrorManager::Medium, 5136, "TCPConnection::HandleRead", "An error occured while parsing binary data.");
               throw;
            }
         }
         else
         {
            std::string s;
            std::istream is(&_receiveBuffer);
            std::getline(is, s, '\r');

            // consume trailing \n on line.
            _receiveBuffer.consume(1);

      #ifdef _DEBUG
            String sDebugOutput;
            sDebugOutput.Format(_T("RECEIVED: %s\r\n"), String(s));
            OutputDebugString(sDebugOutput);
      #endif

            try
            {
               _protocolParser->ParseData(s);
            }
            catch (boost::system::system_error error)
            {
               String message;
               message.Format(_T("An error occured while parsing data. Bytes transferred: %d, ")
                               _T("Data length: %d, Data: %s."), 
                               bytes_transferred, 
                               s.size(), 
                               String(s));

               ReportError(ErrorManager::Medium, 5136, "TCPConnection::HandleRead", message, error);
            }
            catch (...)
            {
               String message;
               message.Format(_T("An error occured while parsing data. Data length: %d, Data: %s."), s.size(), String(s));

               ReportError(ErrorManager::Medium, 5136, "TCPConnection::HandleRead", message);
            }
         }
      }
      catch (...)
      {
         ReportError(ErrorManager::Medium, 5141, "TCPConnection::HandleRead", "An error occurred while handling read operation.");
         throw;
      }
      
      _ProcessOperationQueue();
   }

   void 
   TCPConnection::HandleWrite(const boost::system::error_code& error,  size_t bytes_transferred)
   {

            // Test fix for IOCP crashes
            CriticalSectionScope scope (_criticalSection);

      try
      {
         // Remove the item we have just handled.
         try
         {
            _operationQueue.Pop(IOOperation::BCTSend);
         }
         catch (...)
         {
            ErrorManager::Instance()->ReportError(ErrorManager::High, 5339, "TCPConnection::HandleWrite", "An unknown error occurred while handling buffer write and popping queue.");
            throw;
         }

         if (error.value() != 0)
         {
            ReportDebugMessage("The write operation failed.", error);
            return;
         }

         bool containsQueuedSendOperations = false;

         try
         {
            containsQueuedSendOperations = _operationQueue.ContainsQueuedSendOperation();
         }
         catch (...)
         {
            ErrorManager::Instance()->ReportError(ErrorManager::High, 5339, "TCPConnection::HandleWrite", "An unknown error occurred while handling buffer write and checking if queue contained buffered operations.");
            throw;
         }

         if (!containsQueuedSendOperations)
         {
            try
            {
               _protocolParser->OnDataSent();
            }
            catch (...)
            {
               ErrorManager::Instance()->ReportError(ErrorManager::High, 5339, "TCPConnection::HandleWrite", "An unknown error occurred while handling buffer write and notifying protocol parser that data was sent.");
               throw;
            }

         }

         try
         {
            _ProcessOperationQueue();
         }
         catch (...)
         {
            ErrorManager::Instance()->ReportError(ErrorManager::High, 5339, "TCPConnection::HandleWrite", "An unknown error occurred while handling buffer write and processing the queue.");
            throw;
         }
      }
      catch (...)
      {
         String message;
         message.Format(_T("An unknown error occurred while handling buffer write. Session ID: %d, Transferred bytes: %d"),  GetSessionID(), bytes_transferred);

         ErrorManager::Instance()->ReportError(ErrorManager::High, 5339, "TCPConnection::HandleWrite", message);
         throw;
      }
   }

   IPAddress 
   TCPConnection::GetRemoteEndpointAddress()
   {
      boost::asio::ip::tcp::endpoint remoteEndpoint = GetSocket().remote_endpoint();
      return IPAddress(remoteEndpoint.address());
   }

   unsigned long 
   TCPConnection::GetRemoteEndpointPort() 
   {
      boost::asio::ip::tcp::endpoint remoteEndpoint = GetSocket().remote_endpoint();
      unsigned long port = remoteEndpoint.port();
      return port;
   }


   unsigned long 
   TCPConnection::GetLocalEndpointPort() 
   {
      boost::asio::ip::tcp::endpoint localEndpoint = GetSocket().local_endpoint();

      return localEndpoint.port();

   }

   void
   TCPConnection::SetReceiveBinary(bool binary)
   {
      _receiveBinary = binary;
   }

   String 
   TCPConnection::SafeGetIPAddress()
   {
      try
      {
         IPAddress address = GetSocket().remote_endpoint().address();

         return address.ToString();
      }
      catch (...)
      {
         return "";
      }
   }

   bool
   TCPConnection::IsClient()
   {
      return _remoteServer.GetLength() > 0;
   }

   bool 
   TCPConnection::PrepareSSLContext(boost::asio::ssl::context &ctx)
   {
      boost::system::error_code errorCode;


      AnsiString sSSLCipherList;
      sSSLCipherList = IniFileSettings::Instance()->GetSSLCipherList();

      AnsiString sSSLOptionList;
      sSSLOptionList = IniFileSettings::Instance()->GetSSLOptionList();


      if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - SSLOptionList Option: " + sSSLOptionList));

      if (sSSLCipherList != "") {
         if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - SSLCipherList Option: " + sSSLCipherList));
         SSL_CTX_set_cipher_list(ctx.native_handle(), sSSLCipherList);
      } else if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - SSLCipherList Option not set, skipping."));



      vector<AnsiString> vSSLOptions = StringParser::SplitString(sSSLOptionList,",");
      boost_foreach(AnsiString oneSSLOption, vSSLOptions)
      {
         if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - Found SSL Option: " + oneSSLOption));


         if (oneSSLOption=="default_workarounds")
         {
            ctx.set_options(boost::asio::ssl::context::default_workarounds);
            if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - SSL Option SET: " + oneSSLOption));
         }
         else if (oneSSLOption=="no_sslv2")
         {
            ctx.set_options(boost::asio::ssl::context::no_sslv2);
            if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - SSL Option SET: " + oneSSLOption));
         }
         else if (oneSSLOption=="no_sslv3")
         {
            ctx.set_options(boost::asio::ssl::context::no_sslv3);
            if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - SSL Option SET: " + oneSSLOption));
         }
         else if (oneSSLOption=="no_tlsv1")
         {
            ctx.set_options(boost::asio::ssl::context::no_tlsv1);
            if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - SSL Option SET: " + oneSSLOption));
         }
         else
         {
            if (IniFileSettings::Instance()->GetLogLevel() > 3) LOG_DEBUG(_T("TCPConnection::PrepareSSLContext - SKIPPING UNKNOWN SSL Option: " + oneSSLOption));
         }

         // Possible options
         //SSL_OP_ALL
         //SSL_OP_CIPHER_SERVER_PREFERENCE
         //SSL_OP_NO_SSLv2
         //SSL_OP_NO_SSLv3
         //SSL_OP_NO_TLSv1
         //SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION

      }

      if (errorCode.value() != 0)
      {
         String errorMessage;
         errorMessage.Format(_T("Failed to set default workarounds."));
         ReportInitError(ErrorManager::Medium, 5144, "TCPConnection::PrepareContext", errorMessage, errorCode);

         return false;
      }

      if (IniFileSettings::Instance()->GetUseSSLVerifyPeer())
      {
         ctx.set_verify_mode(boost::asio::ssl::context::verify_peer | boost::asio::ssl::context::verify_fail_if_no_peer_cert, errorCode);
         if (errorCode.value() != 0)
         {
            String errorMessage;
            errorMessage.Format(_T("Failed to enable peer verification."));
            ReportInitError(ErrorManager::Medium, 5144, "TCPConnection::PrepareContext", errorMessage, errorCode);

            return false;
         }

         ctx.add_verify_path(AnsiString(IniFileSettings::Instance()->GetCertificateAuthorityDirectory()), errorCode);
         if (errorCode.value() != 0)
         {
            String errorMessage;
            errorMessage.Format(_T("Failed to add path to Certificate Authority files."));
            ReportInitError(ErrorManager::Medium, 5144, "TCPConnection::PrepareContext", errorMessage, errorCode);
            return false;
         }
      }      

      return true;
   }

   void  
   TCPConnection::SetSecurityRange(shared_ptr<SecurityRange> securityRange)
   {
      _securityRange = securityRange;
   }

   shared_ptr<SecurityRange>
   TCPConnection::GetSecurityRange()
   {
      if (!_securityRange)
      {
         IPAddress address(GetSocket().remote_endpoint().address());

         _securityRange = PersistentSecurityRange::ReadMatchingIP(address);
      }

      return _securityRange;
   }

   shared_ptr<TCPConnection> 
   TCPConnection::GetSharedFromThis()
   {
      return shared_from_this();
   }

   int
   TCPConnection::GetSessionID()
   {
      try
      {
         int sessionID = _protocolParser->GetSessionID();
         return sessionID;
      }
      catch (...)
      {
         return 0;
      }
   }

   bool
   TCPConnection::STARTTLS_Handshake()
   {
      try
      {

         if (_handshakeDone) LOG_DEBUG("TCPConnection::STARTTLS_Handshake _handshakeDone TRUE") else LOG_DEBUG("TCPConnection::STARTTLS_Handshake _handshakeDone FALSE");

         if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG("TCPConnection::STARTTLS_Handshake handshake1");

         _stateSTARTTLS = 2; // 2 means we are starting handshake but not complete yet

         _sslSocket.async_handshake(boost::asio::ssl::stream_base::server,
         boost::bind(&TCPConnection::HandleHandshake, shared_from_this(),
         boost::asio::placeholders::error));

         if (IniFileSettings::Instance()->GetLogLevel() > 9) LOG_DEBUG("TCPConnection::STARTTLS_Handshake handshake3");

         return 1;
      }

            catch (boost::system::system_error error)
            {
               String sMessage;
               sMessage.Format(_T("TCPConnection - STARTTLS_Handshake - Call to async_handshake failed. Error code: %d, Message: %s"), error.code().value(), String(error.what()));
               LOG_TCPIP(sMessage);
               return 0;

            }

   }


   bool
   TCPConnection::GetAllowSTARTTLS()
   {
      try
      {
         if ((_stateSTARTTLS == 1) && !(_handshakeDone)) return true; else return false;
      }
      catch (...)
      {
         return 0;
      }
   }


   bool
   TCPConnection::GetSTARTTLSDone()
   {
      try
      {
         return _handshakeDone;
      }
      catch (...)
      {
         return 0;
      }
   }


}
