#include "host/ref_certs.h"

const unsigned char ref_cert_man[] = {
  0x30, 0x81, 0xfb, 0x30, 0x81, 0xac, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x00, 0xff, 0xff, 
  0xff, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x4d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 
  0x72, 0x65, 0x72, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
  0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 
  0x30, 0x30, 0x5a, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 
  0x4d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 0x72, 0x65, 0x72, 0x30, 0x2c, 0x30, 0x07, 
  0x06, 0x03, 0x7b, 0x30, 0x78, 0x05, 0x00, 0x03, 0x21, 0x00, 0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17,
  0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3, 0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 
  0x2b, 0x46, 0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 
  0x01, 0x0a, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x41, 0x00, 0xb1, 0xef,
  0xe8, 0xeb, 0x43, 0xd9, 0x2e, 0x9f, 0x05, 0x00, 0xcb, 0x63, 0xc3, 0x33, 0x80, 0x0f, 0x8a, 0x1e, 
  0x6c, 0x7b, 0x13, 0x4c, 0x64, 0x10, 0xfb, 0xc6, 0x48, 0xe4, 0x00, 0x9b, 0xc4, 0xf3, 0xdf, 0x12, 
  0xab, 0x69, 0x79, 0x19, 0x5f, 0xb6, 0x02, 0x30, 0x40, 0x38, 0x13, 0xa0, 0x42, 0x59, 0xe2, 0x5a, 
  0x3e, 0x13, 0x8e, 0x9d, 0xa1, 0x10, 0x42, 0x93, 0x0f, 0x58, 0xcd, 0x07, 0xfc, 0x06
};

const int ref_cert_man_len = 254;

const unsigned char sanctum_ca_private_key[] = {
  0x60, 0x9e, 0x84, 0xdf, 0x9b, 0x49, 0x5d, 0xe7, 0xe1, 0xff, 0x76, 0x91, 0xa4, 0xb9, 0xff, 0xed, 
  0x56, 0x49, 0x0c, 0x4e, 0x51, 0x59, 0x4b, 0xa3, 0x7e, 0x85, 0xee, 0x91, 0x6e, 0x7a, 0x6e, 0x7a, 
  0x47, 0xdd, 0xd1, 0x4f, 0x9b, 0x31, 0x2b, 0x90, 0xaa, 0x4e, 0x12, 0x8a, 0x0d, 0xd7, 0xc3, 0x16, 
  0x25, 0xd7, 0x71, 0x41, 0xe4, 0x2d, 0xcb, 0x1e, 0x1b, 0xf8, 0x6a, 0x57, 0x7a, 0x54, 0x00, 0x76
};

const unsigned char sanctum_ca_public_key[] = {
  0x95, 0xb2, 0xcd, 0xbd, 0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23, 
  0x9b, 0xb4, 0x39, 0x31, 0x9d, 0x50, 0x47, 0xb1, 0xee, 0xe5, 0x62, 0xd9, 0xcc, 0x72, 0x6a, 0xc6
};

const unsigned char sanctum_cert_ca[] = {
  0x30, 0x82, 0x01, 0x0c, 0x30, 0x81, 0xbd, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x0f, 0x0f, 
  0x0f, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x30, 0x20, 0x31, 0x1e, 0x30, 0x1c, 
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x15, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 
  0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1e, 0x17, 0x0d, 
  0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 
  0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x20, 0x31, 0x1e, 
  0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x15, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 
  0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x2c, 
  0x30, 0x07, 0x06, 0x03, 0x7b, 0x30, 0x78, 0x05, 0x00, 0x03, 0x21, 0x00, 0x95, 0xb2, 0xcd, 0xbd, 
  0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23, 0x9b, 0xb4, 0x39, 0x31, 
  0x9d, 0x50, 0x47, 0xb1, 0xee, 0xe5, 0x62, 0xd9, 0xcc, 0x72, 0x6a, 0xc6, 0xa3, 0x16, 0x30, 0x14, 
  0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 
  0xff, 0x02, 0x01, 0x0a, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x41, 0x00, 
  0x41, 0x79, 0x58, 0x40, 0x7f, 0xa8, 0xad, 0x8b, 0x36, 0xc9, 0x12, 0x2a, 0x77, 0x10, 0xde, 0x1c, 
  0x9a, 0xc2, 0x26, 0x8a, 0xb7, 0x79, 0xfe, 0x7f, 0xeb, 0x11, 0xfe, 0x6d, 0x97, 0xac, 0x4d, 0x56, 
  0x31, 0xaa, 0x24, 0x5a, 0x8d, 0xee, 0xca, 0x86, 0xef, 0x6e, 0x29, 0x56, 0x17, 0xd9, 0x24, 0xd7, 
  0x3d, 0x5f, 0x05, 0x98, 0x3a, 0xfe, 0x03, 0x03, 0x53, 0x95, 0xe3, 0x2a, 0x2b, 0x88, 0x30, 0x03
};

const int sanctum_cert_ca_len = 272;
