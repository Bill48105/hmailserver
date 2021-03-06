<?php

if (!defined('IN_WEBADMIN'))
   exit();

if (hmailGetAdminLevel() != 2)
	hmailHackingAttemp(); // Not server admin

$tcpipportid 	= hmailGetVar("tcpipportid",0);
$action	      = hmailGetVar("action","");

$obSettings	   = $obBaseApp->Settings();
$obTCPIPPOrts  = $obSettings->TCPIPPorts;

$protocol    = 1;
$portnumber = "";
$UseSSL = 0;
$SSLCertificateID = 0;
$Address = "";

if ($action == "edit")
{
   $obTCPIPPort     = $obTCPIPPOrts->ItemByDBID($tcpipportid);
   $portnumber      = $obTCPIPPort->PortNumber;
   $protocol        = $obTCPIPPort->Protocol;
   $UseSSL          = $obTCPIPPort->UseSSL;
   $SSLCertificateID = $obTCPIPPort->SSLCertificateID;
   $Address          = $obTCPIPPort->Address;
}

?>

<h1><?php EchoTranslation("TCP/IP port")?></h1>

<form action="index.php" method="post" onSubmit="return formCheck(this);">

   <?php
      PrintHidden("page", "background_tcpipport_save");
      PrintHidden("action", "$action");
      PrintHidden("tcpipportid", "$tcpipportid");
   ?>

   
   <div class="tabber">
      <div class="tabbertab">
          <h2><?php EchoTranslation("General")?></h2>            
      
         	<table border="0" width="100%" cellpadding="5">
         		<tr>
         			<td width="20%"><?php EchoTranslation("Protocols")?></td>
         			<td width="80%">
         				<select name="protocol"  style="font-family: Trebuchet MS, Verdana, Arial, Helvetica, sans-serif">
         					<option value="1" <?php if ($protocol == "1") echo "selected";?> ><?php EchoTranslation("SMTP")?></a>
         					<option value="3" <?php if ($protocol == "3") echo "selected";?> ><?php EchoTranslation("POP3")?></a>
         					<option value="5" <?php if ($protocol == "5") echo "selected";?> ><?php EchoTranslation("IMAP")?></a>
         				</select>
                  	</td>			
         		</tr>
               <?php
                   PrintPropertyEditRow("Address", "TCP/IP address", $Address, 15);
               ?>
               <tr>
         			<td><?php EchoTranslation("TCP/IP port")?></td>
         			<td>
            				<input type="text" name="portnumber" value="<?php echo PreprocessOutput($portnumber)?>" checkallownull="false" checktype="number" checkmessage="<?php EchoTranslation("TCP/IP port")?>">
                  	</td>			
         		</tr>
               <?php
                  PrintCheckboxRow("UseSSL", "Use SSL", $UseSSL);
               ?>
               
               <tr>
         			<td><?php EchoTranslation("SSL Certificate")?></td>
         			<td>
         				<select name="SSLCertificateID" style="font-family: Trebuchet MS, Verdana, Arial, Helvetica, sans-serif">
                        <option value="0" <?php if ($SSLCertificateID == 0) echo "selected";?> ><?php EchoTranslation("None")?></a>
         					<?php
                           $SSLCertificates = $obSettings->SSLCertificates;

                           for ($i = 0; $i < $SSLCertificates->Count; $i++)
                           {
                              $SSLCertificate = $SSLCertificates[$i];
                              
                              $id = $SSLCertificate->ID;
                              $name = $SSLCertificate->Name;
                           
                              ?>
                              <option value="<?php echo $id?>" <?php if ($id == "$SSLCertificateID") echo "selected";?> ><?php echo $name?></a>
                              <?php
                              
                
                           }
                           
                        
                        
                        ?>

         				</select>
                  	</td>			
         		</tr>
         	</table>
         </div>
      </div>
      <?php 
         PrintSaveButton();
      ?>      
</form>
