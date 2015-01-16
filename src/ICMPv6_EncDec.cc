/******************************************************************************
* Copyright (c) 2007, 2014  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
*
* Contributors:
*   Endre Kulcsar - initial implementation and initial documentation
******************************************************************************/
//
//  File:               ICMPv6_EncDec.cc
//  Rev:                R2A
//  Prodnr:             CNL 113 631
//  Reference:          RFC 4443          


#include "ICMPv6_Types.hh"

namespace ICMPv6__Types {


#define Get_MSB_ICMPv6(val) (((val) & 0xff00) >> 8)
#define Get_LSB_ICMPv6(val) ((val) & 0x00ff)

// copied from IP protocol module
General__Types::OCT2
Calculate_cksum(const unsigned char *ptr, int datalen)
{
  unsigned long sum = 0;
  unsigned char ret[2];
  
 // Log_function_name_on_enter();
  
  for (int i = 0; i <= datalen - 2; i = i + 2)
    sum += (ptr[i + 1] << 8) + ptr[i]; 

  if (datalen % 2) // datalen is odd
  {
    sum += ptr[datalen - 1];
  }

  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = ~sum;

  ret[0] = Get_LSB_ICMPv6(sum);
  ret[1] = Get_MSB_ICMPv6(sum);
  return OCTETSTRING(2, &ret[0]);
}

OCTETSTRING f__enc__PDU__ICMPv6(const PDU__ICMPv6& pdu,
                             const OCTETSTRING& srcaddr, // from IPv6 header
                             const OCTETSTRING& dstaddr)  //, from IPv6 header
{ 
 TTCN_Buffer buf;
 pdu.encode(PDU__ICMPv6_descr_, buf, TTCN_EncDec::CT_RAW);
 OCTETSTRING ret_val(buf.get_len(), buf.get_data());
 
 // if user gave checksum field as '0000'O then calculate actual checksum, otherwise use what user gave
 if (oct2int(substr(ret_val,2,2)) == 0)
 {   
   //generate pseudo header for checksum calculation
   OCTETSTRING PseudoHeader;  
   PseudoHeader =  srcaddr + dstaddr + int2oct(ret_val.lengthof(),4) + int2oct (0,3) + int2oct(58,1);      
   // RFC 4443  2 -> "The Next Header value used in the pseudo-header is 58.  ('3A'O

   // calculate checksum    
   OCTETSTRING CHECKSUM = Calculate_cksum ( (const unsigned char *) (PseudoHeader + ret_val), 
                    ret_val.lengthof() + 40 ); //  40 is pseudoheader length
                             
   ret_val = substr(ret_val,0,2) + CHECKSUM + substr(ret_val,4,ret_val.lengthof()- 4);
  }
 return ret_val;
} 

BOOLEAN f__ICMPv6__verify__checksum
(
 const OCTETSTRING& stream,
 const OCTETSTRING& srcaddr, // from IPv6 header
 const OCTETSTRING& dstaddr // from IPv6 header
)
{
  OCTETSTRING PseudoHeader;
  PseudoHeader =  srcaddr + dstaddr + int2oct(stream.lengthof(),4) + int2oct (0,3) + int2oct(58,1); 
    
  // stream with checksum field as 0000
  OCTETSTRING stream_w_zero_checksum;
  stream_w_zero_checksum = substr(stream,0,2) + int2oct(0,2) + substr(stream,4,stream.lengthof()- 4);  
  
  // calculate checksum    
  OCTETSTRING CHECKSUM = Calculate_cksum ( (const unsigned char *) (PseudoHeader + stream_w_zero_checksum), 
                     stream_w_zero_checksum.lengthof() + 40 ); 
  
  OCTETSTRING RECEIVED_CHECKSUM = substr(stream,2,2);
    
  if (CHECKSUM !=  RECEIVED_CHECKSUM)
  {    
    TTCN_warning("Incorrect checksum received! \n Expected checksum: %x %x \n Received checksum: %x %x ",
    ((const unsigned char *)CHECKSUM)[0],
    ((const unsigned char *)CHECKSUM)[1],
    ((const unsigned char *) RECEIVED_CHECKSUM)[0],
    ((const unsigned char *) RECEIVED_CHECKSUM)[1]
   ); 
   return FALSE;
  }
  else
  {
   return TRUE;
  }    

}

} // end of namespace ICMPv6__Types
