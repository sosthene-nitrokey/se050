use crate::types::*;
use core::convert::{From, TryFrom};
use byteorder::{ByteOrder, BE};

#[derive(Debug, PartialEq, Eq)]
pub enum Se050Error {
    UnknownError,
    T1Error(T1Error),
}

//SEE AN12413 P. 34 - Table 18. Instruction characteristics constants
pub const APDU_INSTRUCTION_TRANSIENT: u8 = 0x80;
pub const APDU_INSTRUCTION_AUTH_OBJECT: u8 = 0x40;
pub const APDU_INSTRUCTION_ATTEST: u8 = 0x20;

//See AN12413,- Table 19. Instruction constants P. 35 
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduInstruction {
    /* mask:0x1f */
    Write = 0x01,
    Read = 0x02,
    Crypto = 0x03,
    Mgmt = 0x04,
    Process = 0x05,
    ImportExternal = 0x06,
}


// See AN12413,  Table 21. P1KeyType constants P. 35
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduP1KeyType {
    /* mask:0x60 */
    KeyPair = 0x60,
    PrivateKey = 0x40,
    PublicKey = 0x20,
}

// See  AN12413, Table 22. P1Cred constants P. 35 - 36
#[allow(dead_code, clippy::upper_case_acronyms)]
#[repr(u8)]
pub enum Se050ApduP1CredType {
    Default = 0x00,
    EC = 0x01,
    RSA = 0x02,
    AES = 0x03,
    DES = 0x04,
    HMAC = 0x05,
    Binary = 0x06,
    UserID = 0x07,
    Counter = 0x08,
    PCR = 0x09,
    Curve = 0x0b,
    Signature = 0x0c,
    MAC = 0x0d,
    Cipher = 0x0e,
    TLS = 0x0f,
    CryptoObj = 0x10,
}

// See AN12413, 4.3.5 P2 parameter Table 23. P2 constants -P. 36 - 37
#[allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]
#[repr(u8)]
pub enum Se050ApduP2 {
    Default = 0x00,
    Generate = 0x03,
    Create = 0x04,
    Size = 0x07,
    Sign = 0x09,
    Verify = 0x0a,
    Init = 0x0b,
    Update = 0x0c,
    Final = 0x0d,
    Oneshot = 0x0e,
    DH = 0x0f,
    Diversify = 0x10,
    AuthFirstPart2 = 0x12,
    AuthNonfirstPart2 = 0x13,
    DumpKey = 0x14,
    ChangeKeyPart1 = 0x15,
    ChangeKeyPart2 = 0x16,
    KillAuth = 0x17,
    Import = 0x18,
    Export = 0x19,
    SessionCreate = 0x1b,
    SessionClose = 0x1c,
    SessionRefresh = 0x1e,
    SessionPolicy = 0x1f,
    Version = 0x20,
    Memory = 0x22,
    List = 0x25,
    Type = 0x26,
    Exist = 0x27,
    DeleteObject = 0x28,
    DeleteAll = 0x2a,
    SessionUserID = 0x2c,
    HKDF = 0x2d,
    PBKDF = 0x2e,
    I2CM = 0x30,
    I2CMAttested = 0x31,
    MAC = 0x32,
    UnlockChallenge = 0x33,
    CurveList = 0x34,
    SignECDAA = 0x35,
    ID = 0x36,
    EncryptOneshot = 0x37,
    DecryptOneshot = 0x38,
    Attest = 0x3a,
    Attributes = 0x3b,
    CPLC = 0x3c,
    Time = 0x3d,
    Transport = 0x3e,
    Variant = 0x3f,
    Param = 0x40,
    DeleteCurve = 0x41,
    Encrypt = 0x42,
    Decrypt = 0x43,
    Validate = 0x44,
    GenerateOneshot = 0x45,
    ValidateOneshot = 0x46,
    CryptoList = 0x47,
    Random = 0x49,
    TLS_PMS = 0x4a,
    TLS_PRF_CLI_Hello = 0x4b,
    TLS_PRF_SRV_Hello = 0x4c,
    TLS_PRF_CLI_RND = 0x4d,
    TLS_PRF_SRV_RND = 0x4e,
    RAW = 0x4f,
    ImportExt = 0x51,
    SCP = 0x52,
    AuthFirstPart1 = 0x53,
    AuthNonfirstPart1 = 0x54,
}

// See AN12413, 4.3.6 SecureObject type Table 24. SecureObjectType constants   P. 38
#[allow(dead_code, clippy::upper_case_acronyms)]
#[repr(u8)]
pub enum Se050ApduSecObjType {
    ECKeyPair = 0x01,
    ECPrivKey = 0x02,
    ECPubKey = 0x03,
    RSAKeyPair = 0x04,
    RSAKeyPairCRT = 0x05,
    RSAPrivKey = 0x06,
    RSAPrivKeyCRT = 0x07,
    RSAPubKey = 0x08,
    AESKey = 0x09,
    DESKey = 0x0a,
    BinaryFile = 0x0b,
    UserID = 0x0c,
    Counter = 0x0d,
    PCR = 0x0f,
    Curve = 0x10,
    HMACKey = 0x11,
}

// See AN12413,  4.3.7 Memory Table 25. Memory constants  P.38
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduMemoryType {
    Persistent = 1,
    TransientReset = 2,
    TransientDeselect = 3,
}

// See AN12413, 4.3.8 Origin Table 26. Origin constants  P. 38
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduObjectOrigin {
    External = 1,
    Internal = 2,
    Provisioned = 3,
}

// See AN12413,4.3.9 TLV tags Table 27. Tags P.39
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050TlvTag {
    SessionID = 0x10,
    Policy = 0x11,
    MaxAttempts = 0x12,
    ImportAuthData = 0x13,
    ImportAuthKeyID = 0x14,
    Tag1 = 0x41,
    Tag2 = 0x42,
    Tag3 = 0x43,
    Tag4 = 0x44,
    Tag5 = 0x45,
    Tag6 = 0x46,
    Tag7 = 0x47,
    Tag8 = 0x48,
    Tag9 = 0x49,
    Tag10 = 0x4a,
}

// See AN12413,4.3.10 ECSignatureAlgo Table 28. ECSignatureAlgo P.39
//See AN12413, 4.3.22 AttestationAlgo AttestationAlgo is either ECSignatureAlgo or RSASignatureAlgo. P.43
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ECSignatureAlgo {
SIG_ECDSA_PLAIN = 0x09,
SIG_ECDSA_SHA = 0x11,
SIG_ECDSA_SHA_224 = 0x25,
SIG_ECDSA_SHA_256 = 0x21,
SIG_ECDSA_SHA_384 = 0x22,
SIG_ECDSA_SHA_512 = 0x26,

}

// See AN12413, 4.3.11 EDSignatureAlgo Table 29. EDSignatureAlgo P.39
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050EDSignatureAlgo {

    SIG_ED25519PURE = 0xA3,

}

// See AN12413, 4.3.12 ECDAASignatureAlgo Table 30. ECDAASignatureAlgo P.40
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ECDAASignatureAlgo {

    SIG_ECDAA = 0xF4,

}

// See AN12413, 4.3.13 RSASignatureAlgo Table 31. RSASignatureAlgo P.40
//See AN12413, 4.3.22 AttestationAlgo AttestationAlgo is either ECSignatureAlgo or RSASignatureAlgo. P.43
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050RSASignatureAlgo {
    
RSA_SHA1_PKCS1_PSS  = 0x15 ,
RSA_SHA224_PKCS1_PSS = 0x2B ,
RSA_SHA256_PKCS1_PSS = 0x2C ,
RSA_SHA384_PKCS1_PSS = 0x2D ,
RSA_SHA512_PKCS1_PSS = 0x2E,
RSA_SHA1_PKCS1 = 0x0A ,
RSA_SHA_224_PKCS1 = 0x27 ,
RSA_SHA_256_PKCS1 = 0x28 ,
RSA_SHA_384_PKCS1 =  0x29 ,
RSA_SHA_512_PKCS1 = 0x2A ,

}


 // See AN12413, 4.3.14 RSAEncryptionAlgo Table 32. RSAEncryptionAlgo P.40
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050RSAEncryptionAlgo {

    RSA_NO_PAD = 0x0C,
    RSA_PKCS1 = 0x0A,
    RSA_PKCS1_OAEP = 0x0F,

}

 // See AN12413, 4.3.15 RSABitLength Table 33. RSABitLength P.40
 #[allow(dead_code)]
 #[repr(u16)]
 pub enum Se050RSABitLength {

     RSA_512 = 512,
     RSA_1024 = 1024,
     RSA_1152 = 1152,
     RSA_2048 = 2048,
     RSA_3072 = 3072,
     RSA_4096 = 4096,
 
 }
  

// See AN12413, 4.3.16 RSAKeyComponent Table 34. RSAKeyComponentP.41
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050RSAKeyComponent {    
    
    RSA_COMP_MOD = 0x00 ,
    RSA_COMP_PUB_EXP = 0x01 ,
    RSA_COMP_PRIV_EXP = 0x02 ,
    RSA_COMP_P = 0x03 ,
    RSA_COMP_Q  = 0x04 ,
    RSA_COMP_DP  = 0x05 ,
    RSA_COMP_DQ  = 0x06 ,
    RSA_COMP_INVQ  = 0x07 ,

 
}
 

    // See AN12413, 4.3.17 DigestMode Table 35. DigestMode constants P.41
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum Se050DigestModeconstants {
  
    DIGEST_NO_HASH = 0x00,
    DIGEST_SHA = 0x01,
    DIGEST_SHA224 = 0x07,
    DIGEST_SHA256 = 0x04,
    DIGEST_SHA384 = 0x05,
    DIGEST_SHA512 =  0x06,

}

    // See AN12413, 4.3.18 MACAlgo Table 36. MACAlgo constants P.41- 42
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum Se050MACAlgoconstants {
      
    HMAC_SHA1 = 0x18,
    HMAC_SHA256 = 0x19,
    HMAC_SHA384 = 0x1A,
    HMAC_SHA512 = 0x1B,
    CMAC_128  = 0x31,
    DES_MAC4_ISO9797_M2 = 0x05,
    DES_MAC4_ISO9797_1_M2_ALG3 = 0x13,
    DES_MAC4_ISO9797_M1 = 0x03,
    DES_MAC4_ISO9797_1_M1_ALG3 = 0x2F,
    DES_MAC8_ISO9797_M2 = 0x06,
    DES_MAC8_ISO9797_1_M2_ALG3 = 0x14,
    DES_MAC8_ISO9797_1_M1_ALG3 = 0x04,
   // DES_MAC8_ISO9797_1_M1_ALG3 = 0x30,

}
 

    // See AN12413,4.3.19 ECCurve Table 37. ECCurve constants   P.42
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum Se050ECCurveconstants  {
    
    NIST_P192 = 0x01,
    NIST_P224 = 0x02,    
    NIST_P256 = 0x03,
    NIST_P384 = 0x04,
    NIST_P521 = 0x05,

    Brainpool160 = 0x06,
    Brainpool192 = 0x07,
    Brainpool224 = 0x08,
    Brainpool256 = 0x09,
    Brainpool320 = 0x0A,
    Brainpool384 = 0x0B,
    Brainpool512 = 0x0C,
 
    Secp160k1=0x0D,
    Secp192k1=0x0E,
    Secp224k1=0x0F,
    Secp256k1=0x10,
  
    TPM_ECC_BN_P256=0x11,
    ID_ECC_ED_25519= 0x40, 
    ID_ECC_MONT_DH_25519=0x41
 
}


    // See AN12413, 4.3.20 ECCurveParam  Table 38. ECCurveParam constants P 42
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum Se050ECCurveParamconstants {     
    
    CURVE_PARAM_A = 0x01,
    CURVE_PARAM_B = 0x02,
    CURVE_PARAM_G = 0x04,
    CURVE_PARAM_N = 0x08,
    CURVE_PARAM_PRIME = 0x10,

}
 
    // See AN12413,4.3.21 CipherMode Table 39. CipherMode constants   P.43
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050CipherModeconstants {
         
    DES_CBC_NOPAD = 0x01,  
    DES_CBC_ISO9797_M1 = 0x02,
    DES_CBC_ISO9797_M2=0x03,
    DES_CBC_PKCS5=0x04,
    DES_ECB_NOPAD= 0x05,
    DES_ECB_ISO9797_M1= 0x06,
    DES_ECB_ISO9797_M2= 0x07,
    DES_ECB_PKCS5 =0x08,
    AES_ECB_NOPAD =0x0E,
    AES_CBC_NOPAD =0x0D,
    AES_CBC_ISO9797_M1 =0x16,
    AES_CBC_ISO9797_M2 =0x17,
    AES_CBC_PKCS5= 0x18,
    AES_CTR =0xF0,

 
}

    // See AN12413,4.3.23 AppletConfig Table 40. Applet configurations   P.43-44
    #[allow(dead_code)]
    #[repr(u16)]
    pub enum  Se050AppletConfig {

     CONFIG_ECDAA = 0x0001,
     CONFIG_ECDSA_ECDH_ECDHE = 0x0002,
     CONFIG_EDDSA = 0x0004,
     CONFIG_DH_MONT = 0x0008,
     CONFIG_HMAC = 0x0010,
     CONFIG_RSA_PLAIN = 0x0020,
     CONFIG_RSA_CRT =  0x0040,
     CONFIG_AES = 0x0080,
  
     CONFIG_DES = 0x0100,
     CONFIG_PBKDF = 0x0200,
     CONFIG_TLS = 0x0400,
     CONFIG_MIFARE = 0x0800,
     CONFIG_FIPS_MODE_DISABLED = 0x1000,
     CONFIG_I2CM = 0x2000,

     CONFIG_ECC_ALL = 0x000F,
     CONFIG_RSA_ALL = 0x0060,
     CONFIG_ALL = 0x3FFF,

     }



    // See AN12413, 4.3.24 LockIndicator ,Table 41. LockIndicator constants  P.44
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050LockIndicatorconstants { 

    TRANSIENT_LOCK = 0x01,
    PERSISTENT_LOCK = 0x02,
 
}
 
    // See AN12413,  4.3.25 ,   Table 42. LockState constants   P.44
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050LockStateconstants {   

    LOCKED = 0x01,
    UNLOCKED = 0x02,
 
}


    // See AN12413,   4.3.26 CryptoContext , Table 43. P.44
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050CryptoContextconstants { 

        CC_DIGEST = 0x01, 
        CC_CIPHER = 0x02,
        CC_SIGNATURE = 0x03,
    }
     
    // See AN12413,  4.3.27 Result  Table 44. Result constants P.44
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050Resultconstants {     
 
     RESULT_SUCCESS= 0x01,
     RESULT_FAILURE = 0x02,
    }


     // See AN12413,4.3.28  TransientIndicator, Table 45. TransientIndicator constants P.44   
     #[allow(dead_code)]
     #[repr(u8)]
     pub enum  Se050TransientIndicatorconstants {     

     PERSISTENT =0x01,
     TRANSIENT =0x02,

     }
 
   // See AN12413,4.3.28, 4.3.29 SetIndicator  Table 46. SetIndicator constants P.45     
     #[allow(dead_code)]
     #[repr(u8)]
     pub enum  Se050SetIndicatorconstants {     

      NOT_SET = 0x01,
      SET = 0x02,

     }
 
     // See AN12413,4.3.28, 4.3.30 MoreIndicator   Table 47. MoreIndicator constants   P.45  
     #[allow(dead_code)]
     #[repr(u8)]
     pub enum  Se050MoreIndicatorconstants {    

     NO_MORE = 0x01,
     MORE = 0x02,

     }

 

     // See AN12413,4.3.28, 4.3.31 PlatformSCPRequest , Table 48. PlatformSCPRequest constants P.45
    #[allow(dead_code)]
     #[repr(u8)]
     pub enum  Se050PlatformSCPRequestconstants {    

     SCP_REQUIRED = 0x01 ,
     SCP_NOT_REQUIRED = 0x02,

     }
 
 

include!("se050_convs.rs");

//////////////////////////////////////////////////////////////////////////////
//trait-Se050Device ->  struct Se050
pub trait Se050Device {
    
    fn enable(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    fn disable(&mut self, _delay: &mut DelayWrapper);

   
    fn SetAppletFeatures(&mut self,AppletConfig: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> ;




//See AN12413,4.5 Session management // 4.5.1 Generic session commands //4.5.1.1 CreateSession P.48

    fn CreateSession(&mut self,  authobjid: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

//See AN12413,4.5 Session management // 4.5.1 Generic session commands //4.5.1.2 ExchangeSessionData P.49

    fn ExchangeSessionData(&mut self,  SessionPolicies: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands /4.5.1.3 ProcessSessionCmd P.49-50
    fn ProcessSessionCmd(&mut self,APDUcommand : &[u8], SessionID : &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.4 RefreshSession P.50
    fn RefreshSession(&mut self,Policy: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.4 RefreshSession P.50
    fn CloseSession(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> ;


//See AN12413 , 4.5 Session management //4.5.2 UserID session operations // 4.5.2.1 VerifySessionUserID P.51-52

 
fn VerifySessionUserID(&mut self, UserIDvalue: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error>;



   // See AN12413, // 4.7 Secure Object management // P57-58

    // See AN12413,  4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey //P1_EC ///P.58-59
 
    fn generate_ECCURVE_key(&mut self, ECCurve: &[u8], delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error>; //ERWEITERT
    
    fn generate_p256_key(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error>; //DEFAULT CONFIGURATION OF SE050

     
    // See AN12413,  4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.2 WriteRSAKey  //P.59-60

    /*
    TO-DO  ->FUNCTIONS TO GENERATE RSA-KEY


    */

    // See AN12413 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey //AES key, DES key or HMAC key // P 60/ P.61

    fn write_aes_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    fn write_des_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;
    
    fn write_hmac_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;


    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.4 WriteBinary  //P.61

    /*
    TO-DO  ->FUNCTIONS  FOR Creating or writimg to a binary file object

    */

  // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject P.57 //4.7.1.5 WriteUserID  //P.62
 
  fn WriteUserID(&mut self, UserIdentifierValue : &[u8], delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error>;
  
     /*
    TO-DO  ->FUNCTIONS  FOR Creating or writing  a UserID object, setting the user identifier value.  
    VerifySessionUserID 0x80 0x04 0x00 0x2C
    WriteUserID 0x80 0x01 0x07 0x00

    */
 


    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.6 WriteCounter  //P.62

     /*
    TO-DO  ->FUNCTIONS  FOR Creating or writing to a counter object.

    */



    //4.12 Crypto operations AES/DES  //4.12.4 CipherOneShot - Encrypt or decrypt data in one shot mode //P.87

    /* 
        fn encrypt_aes_oneshot(
            &mut self,
            data: &[u8],
            enc: &mut [u8],
            delay: &mut DelayWrapper,
        ) -> Result<(), Se050Error>;
    */

    //fn encrypt_aes_oneshot( &mut self,   data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
    fn encrypt_aes_oneshot( &mut self,  CipherMode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
    fn decrypt_aes_oneshot( &mut self,  CipherMode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
    
    fn encrypt_des_oneshot( &mut self,  CipherMode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
    fn decrypt_des_oneshot( &mut self,  CipherMode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
         
    // See AN12413, //4.19 Generic management commands // P110-11
    fn get_random(&mut self, buf: &mut [u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

}

//struct Se050AppInfo ->no further Implementation 20221026
#[allow(dead_code)]
#[derive(Debug)]
pub struct Se050AppInfo {
    applet_version: u32,
    features: u16,
    securebox_version: u16,
}
//STRUCT SE050
pub struct Se050<T>
where
    T: T1Proto,
{
    t1_proto: T,
    atr_info: Option<AnswerToReset>,
    app_info: Option<Se050AppInfo>,
}
 
//impl- > for struct SE050 ->new function
impl<T> Se050<T>
where
    T: T1Proto,
{
    pub fn new(t1: T) -> Se050<T> {
        Se050 {
            t1_proto: t1,
            atr_info: None,
            app_info: None,
        }
    }
}
//impl- > for struct SE050 ->functions
impl<T> Se050Device for Se050<T>
where
    T: T1Proto,
{

 

    fn enable(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        /* Step 1: perform interface soft reset, parse ATR */
        let r = self.t1_proto.interface_soft_reset(delay);
        if r.is_err() {
            error!("SE050 Interface Reset Error");
            return Err(Se050Error::UnknownError);
        }
        self.atr_info = r.ok();
        debug!("SE050 ATR: {:?}", self.atr_info.as_ref().unwrap());

        /* Step 2: send GP SELECT to choose SE050 JCOP APP, parse APP version */
        let app_id: [u8; 16] = [
            0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00,
            0x00, 0x00,
        ];
        let app_select_apdu = RawCApdu {
            cla: ApduClass::StandardPlain,
            ins: ApduStandardInstruction::SelectFile.into(),
            p1: 0x04,
            p2: 0x00,
            data: &app_id,
            le: Some(0),
        };
        self.t1_proto.send_apdu_raw(&app_select_apdu, delay).map_err(|_| Se050Error::UnknownError)?;

        let mut appid_data: [u8; 11] = [0; 11];
        let appid_apdu = self.t1_proto
            .receive_apdu_raw(&mut appid_data, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let adata = appid_apdu.data;
        let asw = appid_apdu.sw;
        if asw != 0x9000 || adata.len() != 7 {
            error!("SE050 GP SELECT Err: {:?} {:x}", delog::hex_str!(adata), asw);
            return Err(Se050Error::UnknownError);
        }

        self.app_info = Some(Se050AppInfo {
            applet_version: BE::read_uint(&adata[0..3], 3) as u32,
            features: BE::read_u16(&adata[3..5]),
            securebox_version: BE::read_u16(&adata[5..7]),
        });
        debug!("SE050 App: {:?}", self.app_info.as_ref().unwrap());

        Ok(())
    }

    fn disable(&mut self, _delay: &mut DelayWrapper) {
        // send S:EndApduSession
        // receive ACK
        // power down
    }

//###########################################################################
//See AN12413, 4.5 Session management // 4.5.1 Generic session commands //4.5.1.1 CreateSession P.48
// Creates a session on SE050.
//Depending on the authentication object being referenced, a specific method of authentication applies. 
//The response needs to adhere to this authentication method.

// authentication object identifier -> authobjid


#[inline(never)]
fn CreateSession(&mut self,  authobjid: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> {
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &authobjid);
   
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt ) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::SessionCreate.into(),
        Some(12)
    );
    capdu.push(tlv1);
   
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 CreateSession Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 CreateSession OK");
    Ok(())
}


//###########################################################################
//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.2 ExchangeSessionData P.49
// Sets session policies for the current session.
 // Session policies -> SessionPolicies


#[inline(never)]
fn ExchangeSessionData(&mut self,  SessionPolicies: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> {
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &SessionPolicies);
   
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt ) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::SessionPolicy.into(),
        Some(0)
    );
    capdu.push(tlv1);
   
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 ExchangeSessionData Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 ExchangeSessionData OK");
    Ok(())
}




     //###########################################################################
//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands /4.5.1.3 ProcessSessionCmd P.49-50
//Requests a command to be processed within a specific session. 
//Note that the applet does not check the validity of the CLA byte of the TLV[TAG_1] payload.

     #[inline(never)]
     
     fn ProcessSessionCmd(&mut self,APDUcommand : &[u8], SessionID : &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {

         let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &APDUcommand);

         let tlv = SimpleTlv::new(Se050TlvTag::SessionID.into(), &SessionID);	

        
         let mut capdu = CApdu::new(
             ApduClass::ProprietaryPlain,
             Into::<u8>::into(Se050ApduInstruction::Process) | APDU_INSTRUCTION_TRANSIENT,
             Se050ApduP1CredType::Default.into(),
             Se050ApduP2::Default.into(),
             Some(0)
         );
         capdu.push(tlv1);
         capdu.push(tlv);
     
         self.t1_proto
             .send_apdu(&capdu, delay)
             .map_err(|_| Se050Error::UnknownError)?;
 
         let mut rapdu_buf: [u8; 16] = [0; 16];
         let rapdu = self.t1_proto
             .receive_apdu(&mut rapdu_buf, delay)
             .map_err(|_| Se050Error::UnknownError)?;
 
         if rapdu.sw != 0x9000 {
             error!("SE050 ProcessSessionCmd: {:x}", rapdu.sw);
             return Err(Se050Error::UnknownError);
         }
 
         debug!("SE050 ProcessSessionCmd OK");
         Ok(())
     }
 
 //###########################################################################

//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.4 RefreshSession P.50

#[inline(never)]
     
fn RefreshSession(&mut self,Policy: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {

    let tlv = SimpleTlv::new(Se050TlvTag::Policy.into(), &Policy);
 
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2:: SessionRefresh.into(),
        None
    );
    capdu.push(tlv);
    

    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 RefreshSession: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 RefreshSession OK");
    Ok(())
}



 //###########################################################################

//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands 4.5.1.5 CloseSession P.50
//Closes a running session.
//When a session is closed, it cannot be reopened.
//All session parameters are transient.
//If CloseSession returns a Status Word different from SW_NO_ERROR, the applet immediately needs to be reselected as further APDUs would not be handled successfully.
 

#[inline(never)]
     
fn CloseSession(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
   
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::SessionClose.into(),
        None
    );
    
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 CloseSession: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050CloseSession OK");
    Ok(())
}


 //###########################################################################

 //See AN12413 , 4.5 Session management //4.5.2 UserID session operations // 4.5.2.1 VerifySessionUserID P.51-52

 #[inline(never)]
 
 fn VerifySessionUserID(&mut self, UserIDvalue: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> {
     let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &UserIDvalue);
      
     let mut capdu = CApdu::new(
         ApduClass::ProprietaryPlain,
         Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
         Se050ApduP1CredType::Default.into(),
         Se050ApduP2::SessionUserID.into(),
         None
     );
     capdu.push(tlv1);
      
     self.t1_proto
         .send_apdu(&capdu, delay)
         .map_err(|_| Se050Error::UnknownError)?;

     let mut rapdu_buf: [u8; 16] = [0; 16];
     let rapdu = self.t1_proto
         .receive_apdu(&mut rapdu_buf, delay)
         .map_err(|_| Se050Error::UnknownError)?;

     if rapdu.sw != 0x9000 {
         error!("SE050 VerifySessionUserID Failed: {:x}", rapdu.sw);
         return Err(Se050Error::UnknownError);
     }

     debug!("SE050 VerifySessionUserID OK");
     Ok(())
 }





 //4.5.3 AESKey session operations // 4.5.3.1 SCPInitializeUpdate
  //[SCP03] Section 7.1.1 shall be applied.
// The user shall always set the P1 parameter to ‘00’ (KVN = ‘00’).


 //4.5.3.2 SCPExternalAuthenticate
 //[SCP03] Section 7.1.2 shall be applied.


 // 4.5.4 ECKey session operations // 4.5.4.1 ECKeySessionInternalAuthenticate P.52
 
 //Initiates an authentication based on an ECKey Authentication Object. 
 //See  Section 3.6.3.3 for more information.
 //The user shall always use key version number = ‘00’ and key identifier = ‘00’.


 //###########################################################################
 
    #[inline(never)]
    /* ASSUMPTION: SE050 is provisioned with an instantiated ECC curve object; */
           /* NOTE: hardcoded Object ID 0xae51ae51! */
     //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey    P.58
    //P1_EC 4.3.19 ECCurve P.42
    fn generate_ECCURVE_key(&mut self, ECCurve: &[u8],delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x51, 0xae, 0x51]);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &ECCurve );	// Se050ECCurveconstants
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
            Se050ApduP2::Default.into(),
            None
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 GenECCurve {:x} Failed: {:x}", ECCurve, rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 GenECCurvev {:x} : OK",ECCurve);
        Ok(ObjectId([0xae, 0x51, 0xae, 0x51]))
    }


     //###########################################################################
    #[inline(never)]
    /* ASSUMPTION: SE050 is provisioned with an instantiated P-256 curve object;
        see NXP AN12413 -> Secure Objects -> Default Configuration */
    /* NOTE: hardcoded Object ID 0xae51ae51! */
     //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey   P.58
      //P1_EC //  4.3.19 ECCurve NIST_P256 P.42
    fn generate_p256_key(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x51, 0xae, 0x51]);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x03]);	// NIST P-256
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
            Se050ApduP2::Default.into(),
            None
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 GenP256 Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 GenP256 OK");
        Ok(ObjectId([0xae, 0x51, 0xae, 0x51]))
    }


//###########################################################################

    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
      //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60 
      //P1_AES //template for 
    fn write_aes_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        if key.len() != 16 {
            todo!();
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::AES.into(),
            Se050ApduP2::Default.into(),
            Some(0)
        );
        capdu.push(tlv1);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 WriteAESKey Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }



    //##################################################

    //ERWEITERT
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
    //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60 
    //P1_DES
    fn write_des_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        if key.len() != 16 {
            todo!();
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::DES.into(),
            Se050ApduP2::Default.into(),
            Some(0)
        );
        capdu.push(tlv1);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 WriteDESKey Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //##################################################   

    //ERWEITERT
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
    //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60 
    //P1_HMAC
    fn write_hmac_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
    if key.len() != 16 {
        todo!();
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::HMAC.into(),
        Se050ApduP2::Default.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 WriteHMACKey Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    Ok(())
    }

 
/*  
  //###########################################################################
  
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    //4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT//  4.3.21 CipherMode // AES CBC NOPAD
    fn encrypt_aes_oneshot(&mut self, data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
    {
        if data.len() > 240 || (data.len() % 16 != 0) {
            error!("Input data too long or unaligned");
            return Err(Se050Error::UnknownError);
        }
        if enc.len() != data.len() {
            error!("Insufficient output buffer");
            return Err(Se050Error::UnknownError);
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x0d]);	// AES CBC NOPAD
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Se050ApduInstruction::Crypto.into(),
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::EncryptOneshot.into(),
            Some(0)
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 EncryptAESOneshot Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            error!("SE050 EncryptAESOneshot Return TLV Missing");
            Se050Error::UnknownError })?;

        if tlv1_ret.get_data().len() != enc.len() {
            error!("SE050 EncryptAESOneshot Length Mismatch");
            return Err(Se050Error::UnknownError);
        }
        enc.copy_from_slice(tlv1_ret.get_data());
        debug!("SE050 EncryptAESOneshot OK");
        Ok(())
    }
 */

// VerifySessionUserID 0x80 0x04 0x00 0x2C


#[inline(never)]
//WriteUserID 0x80 0x01 0x07 0x00
/* NOTE: hardcoded Object ID 0xae51ae51! */
// See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject P.57 //4.7.1.5 WriteUserID  //P.62
fn WriteUserID(&mut self, UserIdentifierValue : &[u8], delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> {
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x51, 0xae, 0x51]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &UserIdentifierValue );	 
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::UserID.into(),
        Se050ApduP2::Default.into(),
        None
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 WriteUserID  Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 WriteUserID OK");
    Ok(ObjectId([0xae, 0x51, 0xae, 0x51]))
}


//###########################################################################
  
#[inline(never)]
/* NOTE: hardcoded Object ID 0xae50ae50! */
//4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT P.87
//  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
fn encrypt_aes_oneshot(&mut self, CipherMode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
{
    if data.len() > 240 || (data.len() % 16 != 0) {
        error!("Input data too long or unaligned");
        return Err(Se050Error::UnknownError);
    }
    if enc.len() != data.len() {
        error!("Insufficient output buffer");
        return Err(Se050Error::UnknownError);
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &CipherMode);	// 4.3.21 CipherMode Table 39. CipherMode constants
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Se050ApduInstruction::Crypto.into(),
        Se050ApduP1CredType::Cipher.into(),
        Se050ApduP2::EncryptOneshot.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 EncryptAESOneshot {:x} Failed: {:x}", CipherMode, rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
        error!("SE050 EncryptAESOneshot Return TLV Missing");
        Se050Error::UnknownError })?;

    if tlv1_ret.get_data().len() != enc.len() {
        error!("SE050 EncryptAESOneshot Length Mismatch");
        return Err(Se050Error::UnknownError);
    }
    enc.copy_from_slice(tlv1_ret.get_data());
    debug!("SE050 EncryptAESOneshot {:x} OK", CipherMode );
    Ok(())
}


//###########################################################################
//ERWEITERT
#[inline(never)]
/* NOTE: hardcoded Object ID 0xae50ae50! */
//4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // DECRYPT P.87
//  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
fn decrypt_aes_oneshot(&mut self, CipherMode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
{
    if data.len() > 240 || (data.len() % 16 != 0) {
        error!("Input data too long or unaligned");
        return Err(Se050Error::UnknownError);
    }
    if enc.len() != data.len() {
        error!("Insufficient output buffer");
        return Err(Se050Error::UnknownError);
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(),  &CipherMode);	// 4.3.21 CipherMode Table 39. CipherMode constants
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Se050ApduInstruction::Crypto.into(),
        Se050ApduP1CredType::Cipher.into(),
        Se050ApduP2::DecryptOneshot.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 DecryptAESOneshot {:x}, Failed: {:x}", CipherMode,rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
        error!("SE050 DecryptAESOneshot_{:x} Return TLV Missing",  CipherMode);
        Se050Error::UnknownError })?;

    if tlv1_ret.get_data().len() != enc.len() {
        error!("SE050 DecryptAESOneshot {:x} Length Mismatch", CipherMode );
        return Err(Se050Error::UnknownError);
    }
    enc.copy_from_slice(tlv1_ret.get_data());
    debug!("SE050 DecryptAESOneshot {:x} OK",CipherMode );
    Ok(())
}





//###########################################################################
  
#[inline(never)]
/* NOTE: hardcoded Object ID 0xae50ae50! */
//4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT  P.87
//  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
fn encrypt_des_oneshot(&mut self, CipherMode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
{
    if data.len() > 240 || (data.len() % 16 != 0) {
        error!("Input data too long or unaligned");
        return Err(Se050Error::UnknownError);
    }
    if enc.len() != data.len() {
        error!("Insufficient output buffer");
        return Err(Se050Error::UnknownError);
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &CipherMode);	// 4.3.21 CipherMode Table 39. CipherMode constants
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Se050ApduInstruction::Crypto.into(),
        Se050ApduP1CredType::Cipher.into(),
        Se050ApduP2::EncryptOneshot.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 EncryptDESOneshot {:x} Failed: {:x}", CipherMode, rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
        error!("SE050 EncryptDESOneshot Return TLV Missing");
        Se050Error::UnknownError })?;

    if tlv1_ret.get_data().len() != enc.len() {
        error!("SE050 EncryptDESOneshot Length Mismatch");
        return Err(Se050Error::UnknownError);
    }
    enc.copy_from_slice(tlv1_ret.get_data());
    debug!("SE050 EncryptDESOneshot {:x} OK", CipherMode );
    Ok(())
}


//###########################################################################
//ERWEITERT
#[inline(never)]
/* NOTE: hardcoded Object ID 0xae50ae50! */
//4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // DECRYPT P.87 
//  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
fn decrypt_des_oneshot(&mut self, CipherMode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
{
    if data.len() > 240 || (data.len() % 16 != 0) {
        error!("Input data too long or unaligned");
        return Err(Se050Error::UnknownError);
    }
    if enc.len() != data.len() {
        error!("Insufficient output buffer");
        return Err(Se050Error::UnknownError);
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(),  &CipherMode);	// 4.3.21 CipherMode Table 39. CipherMode constants
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Se050ApduInstruction::Crypto.into(),
        Se050ApduP1CredType::Cipher.into(),
        Se050ApduP2::DecryptOneshot.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 DecryptDESOneshot {:x}, Failed: {:x}", CipherMode,rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
        error!("SE050 DecryptDESOneshot_{:x} Return TLV Missing",  CipherMode);
        Se050Error::UnknownError })?;

    if tlv1_ret.get_data().len() != enc.len() {
        error!("SE050 DecryptDESOneshot {:x} Length Mismatch", CipherMode );
        return Err(Se050Error::UnknownError);
    }
    enc.copy_from_slice(tlv1_ret.get_data());
    debug!("SE050 DecryptDESOneshot {:x} OK",CipherMode );
    Ok(())
}

//###########################################################################
 //AN12413 // 4.6 Module management  //4.6.3 SetAppletFeatures  P.56 -57
 // Sets the applet features that are supported. 
 // To successfully execute this command, the session must be authenticated using the RESERVED_ID_FEATURE.
//The 2-byte input value is a pre-defined AppletConfig value.


     #[inline(never)]    
    fn SetAppletFeatures(&mut self,AppletConfig: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &AppletConfig);
       
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Default.into(),
            None
        );
        capdu.push(tlv1);
         
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050  SetAppletFeatures Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050  SetAppletFeatures OK");
        Ok(())
    }





 
 //###########################################################################
    //AN12413, Pages 110/111 -> 4.19 Generic management commands //4.19.4 GetRandom (Gets random data from the SE050.) p.110
    #[inline(never)]
    fn get_random(&mut self, buf: &mut [u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut buflen: [u8; 2] = [0, 0];
        BE::write_u16(&mut buflen, buf.len() as u16);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &buflen);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Se050ApduInstruction::Mgmt.into(),
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Random.into(),
            Some(0)
        );
        capdu.push(tlv1);
        self.t1_proto.send_apdu(&capdu, delay).map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 GetRandom Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            error!("SE050 GetRandom Return TLV Missing");
            Se050Error::UnknownError })?;

        if tlv1_ret.get_data().len() != buf.len() {
            error!("SE050 GetRandom Length Mismatch");
            return Err(Se050Error::UnknownError);
        }
        buf.copy_from_slice(tlv1_ret.get_data());
        debug!("SE050 GetRandom OK");
        Ok(())
    }
 

}
