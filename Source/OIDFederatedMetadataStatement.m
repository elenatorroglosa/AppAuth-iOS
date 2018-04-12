//
//  OIDFederatedMetadataStatement.m
//  AppAuth
//
//  Created by Elena Torroglosa on 19/11/17.
//  Copyright © 2017 OpenID Foundation. All rights reserved.
//

#import "OIDFederatedMetadataStatement.h"
#import "OIDErrorUtilities.h"
#import <JWT/JWT.h>
#import <JWT/JWTAlgorithmFactory.h>
#import <JWT/JWTClaimsSetSerializer.h>

#import <Base64/MF_Base64Additions.h>

//#import <JWT/JWTBuilder.h>
//#import <JWT/JWTAlgorithmDataHolder.h>
//#import <JWT/JWTAlgorithmRSBase.h>
//#import <JWT/JWTAlgorithmNone.h>
//#import <JWT/JWTRSAlgorithm.h>
//#import <JWT/JWTAlgorithmDataHolderChain.h>

#import <openssl/rsa.h>
#include <openssl/engine.h>
#import <openssl/pem.h>

@implementation OIDFederatedMetadataStatement

static inline char itoh(int i) {
    if (i > 9) return 'A' + (i - 10);
    return '0' + i;
}

+(NSString *) NSDataToHex: (NSData *) data {
    NSUInteger i, len;
    unsigned char *buf, *bytes;

    len = data.length;
    bytes = (unsigned char*)data.bytes;
    buf = malloc(len*2);

    for (i=0; i<len; i++) {
        buf[i*2] = itoh((bytes[i] >> 4) & 0xF);
        buf[i*2+1] = itoh(bytes[i] & 0xF);
    }

    return [[NSString alloc] initWithBytesNoCopy:buf
                                          length:len*2
                                        encoding:NSASCIIStringEncoding
                                    freeWhenDone:YES];
}

+(NSString *) convertFromJWKtoPEM_PrivateKey: (NSDictionary *)jwk {

    NSLog(@"EMTG - starting convertFromJWKtoPEM_PrivateKey");
    RSA * rsaKey = RSA_new();

    ENGINE * rsaEngine = ENGINE_new();
    //ENGINE_get_default_RSA();
    int eng_init_result = ENGINE_init(rsaEngine);
    if (eng_init_result == 0)
        NSLog(@"EMTG - Error initializing the rsaEngine");

    rsaKey->engine = rsaEngine;

    BIGNUM *n_bn = NULL, *e_bn = NULL;
    BIGNUM *d_bn = NULL, *p_bn = NULL, *q_bn = NULL;

    e_bn = BN_new();
    n_bn = BN_new();
    d_bn = BN_new();
    p_bn = BN_new();
    q_bn = BN_new();

    NSString * nzu = [jwk objectForKey:@"n"]; // public modulus
    NSString * ezu = [jwk objectForKey:@"e"]; // public exponent
    NSString * dzu = [jwk objectForKey:@"d"]; // private exponent
    NSString * pzu = [jwk objectForKey:@"p"]; // secret prime factor
    NSString * qzu = [jwk objectForKey:@"q"]; // secret prime factor

    NSString *nz = [MF_Base64Codec base64StringFromBase64UrlEncodedString:nzu];
    NSData *nn = [[NSData alloc]
                  initWithBase64EncodedString:nz
                  options:0];

    NSString *ez = [MF_Base64Codec base64StringFromBase64UrlEncodedString:ezu];
    NSData *en = [[NSData alloc]
                  initWithBase64EncodedString:ez
                  options:0];

    NSString *dz = [MF_Base64Codec base64StringFromBase64UrlEncodedString:dzu];
    NSData *dn = [[NSData alloc]
                  initWithBase64EncodedString:dz
                  options:0];

    NSString *pz = [MF_Base64Codec base64StringFromBase64UrlEncodedString:pzu];
    NSData *pn = [[NSData alloc]
                  initWithBase64EncodedString:pz
                  options:0];

    NSString *qz = [MF_Base64Codec base64StringFromBase64UrlEncodedString:qzu];
    NSData *qn = [[NSData alloc]
                  initWithBase64EncodedString:qz
                  options:0];

    NSString * ehexString = [self NSDataToHex:en];
    NSString * nhexString = [self NSDataToHex:nn];
    NSString * dhexString = [self NSDataToHex:dn];
    NSString * phexString = [self NSDataToHex:pn];
    NSString * qhexString = [self NSDataToHex:qn];

    NSLog(@"EMTG - load param n: \n%@", nz);
    NSLog(@"EMTG - load param e: \n%@", ez);
    NSLog(@"EMTG - load param d: \n%@", dz);
    NSLog(@"EMTG - load param d: \n%@", pz);
    NSLog(@"EMTG - load param d: \n%@", qz);
    NSLog(@"EMTG - nn converted from b64urlformat: %@", nn.debugDescription);
    NSLog(@"EMTG - en converted from b64urlformat: %@", en.debugDescription);
    NSLog(@"EMTG - dn converted from b64urlformat: %@", dn.debugDescription);
    NSLog(@"EMTG - dn converted from b64urlformat: %@", pn.debugDescription);
    NSLog(@"EMTG - dn converted from b64urlformat: %@", qn.debugDescription);
    NSLog(@"EMTG - en converted to hexadecimal: %@", ehexString);
    NSLog(@"EMTG - nn converted to hexadecimal: %@", nhexString);
    NSLog(@"EMTG - dn converted to hexadecimal: %@", dhexString);
    NSLog(@"EMTG - dn converted to hexadecimal: %@", phexString);
    NSLog(@"EMTG - dn converted to hexadecimal: %@", qhexString);

    const char *e_char = [ehexString UTF8String];
    const char *n_char = [nhexString UTF8String];
    const char *d_char = [dhexString UTF8String];
    const char *p_char = [phexString UTF8String];
    const char *q_char = [qhexString UTF8String];

    //int BN_hex2bn(BIGNUM **a, const char *str);
    int res1 = BN_hex2bn(&e_bn, e_char);
    int res2 = BN_hex2bn(&n_bn, n_char);
    int res3 = BN_hex2bn(&d_bn, d_char);
    int res4 = BN_hex2bn(&p_bn, p_char);
    int res5 = BN_hex2bn(&q_bn, q_char);

    rsaKey->e = e_bn;
    rsaKey->n = n_bn;
    rsaKey->d = d_bn;
    rsaKey->p = p_bn;
    rsaKey->q = q_bn;

    ////////// DELETE - DEBUG //////////
    NSString * tmpRSAFilePath = [NSTemporaryDirectory() stringByAppendingPathComponent: [NSString stringWithFormat: @"%.0f.%@", [NSDate timeIntervalSinceReferenceDate] * 1000.0, @"txt"]];
    FILE *tmpRSAFile = fopen([tmpRSAFilePath cStringUsingEncoding:NSUTF8StringEncoding], "w+");

    int rsa_print = RSA_print_fp(tmpRSAFile, rsaKey, 0);
    fclose(tmpRSAFile);
    NSString * fileContents = [NSString stringWithContentsOfFile:tmpRSAFilePath encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"EMTG - RSA_print_fp:\n%@", fileContents);
    /////////////////

    NSString * tmpPEMFilePath = [NSTemporaryDirectory() stringByAppendingPathComponent: [NSString stringWithFormat: @"%.0f.%@", [NSDate timeIntervalSinceReferenceDate] * 1000.0, @"txt"]];
    FILE *tmpPEMFile = fopen([tmpPEMFilePath cStringUsingEncoding:NSUTF8StringEncoding], "w+");

    //int res_conversion = PEM_write_RSAPublicKey(tmpPEMFile, rsaKey); <--- wrong for public conversion
    //int res_conversion = PEM_write_RSA_PUBKEY(tmpPEMFile, rsaKey); <-- right for public conversion
    //int res_conversion = PEM_write_RSAPrivateKey(tmpPEMFile, rsaKey, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
    int res_conversion = PEM_write_RSAPrivateKey(tmpPEMFile, rsaKey, nil, nil, 0, nil, nil);

    fclose(tmpPEMFile);
    NSLog(@"EMTG - conversion result form RSA to PEM (private key): %d", res_conversion);

    // read the contents into a string
    NSString *pemStr = [[NSString alloc]initWithContentsOfFile:tmpPEMFilePath encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"EMTG - PEM Private String content:\n%@", pemStr);

    NSString * pemResult = [pemStr componentsSeparatedByString:@"-----"][2]; //TODO have in mind possible fails related to '\n'
    NSLog(@"EMTG - PEM Private String result:\n%@", pemResult);

    ENGINE_finish(rsaEngine);
    RSA_free(rsaKey);

    return pemResult; //<-- exception of type NSException
    //return pemStr;
}


+(NSString *) convertFromJWKtoPEM_PublicKey: (NSDictionary *)jwk {

    NSLog(@"EMTG - starting convertFromJWKtoPEM");
    RSA * rsaKey = RSA_new();

    ENGINE * rsaEngine = ENGINE_new();
    //ENGINE_get_default_RSA();
    int eng_init_result = ENGINE_init(rsaEngine);
    if (eng_init_result == 0)
        NSLog(@"EMTG - Error initializing the rsaEngine");

    rsaKey->engine = rsaEngine;

    BIGNUM *n_bn = NULL, *e_bn = NULL;
    //BIGNUM *d = NULL, *p = NULL, *q = NULL;

    e_bn = BN_new();
    n_bn = BN_new();

    NSString * nzu = [jwk objectForKey:@"n"]; // public modulus
    NSString * ezu = [jwk objectForKey:@"e"]; // public exponent

    NSString *nz = [MF_Base64Codec base64StringFromBase64UrlEncodedString:nzu];
    NSData *nn = [[NSData alloc]
                               initWithBase64EncodedString:nz
                               options:0];

    NSString *ez = [MF_Base64Codec base64StringFromBase64UrlEncodedString:ezu];
    NSData *en = [[NSData alloc]
                  initWithBase64EncodedString:ez
                  options:0];

    NSString * ehexString = [self NSDataToHex:en];
    NSString * nhexString = [self NSDataToHex:nn];
    
    NSLog(@"EMTG - load param n: \n%@", nz);
    NSLog(@"EMTG - load param e: \n%@", ez);
    NSLog(@"EMTG - nn converted from b64urlformat: %@", nn.debugDescription);
    NSLog(@"EMTG - en converted from b64urlformat: %@", en.debugDescription);
    NSLog(@"EMTG - en converted to hexadecimal: %@", ehexString);
    NSLog(@"EMTG - nn converted to hexadecimal: %@", nhexString);

    const char *e_char = [ehexString UTF8String];
    const char *n_char = [nhexString UTF8String];

    //int BN_hex2bn(BIGNUM **a, const char *str);
    int res1 = BN_hex2bn(&e_bn, e_char);
    int res2 = BN_hex2bn(&n_bn, n_char);

    rsaKey->e = e_bn;
    rsaKey->n = n_bn;

    ////////// DELETE - DEBUG //////////
    NSString * tmpRSAFilePath = [NSTemporaryDirectory() stringByAppendingPathComponent: [NSString stringWithFormat: @"%.0f.%@", [NSDate timeIntervalSinceReferenceDate] * 1000.0, @"txt"]];
    FILE *tmpRSAFile = fopen([tmpRSAFilePath cStringUsingEncoding:NSUTF8StringEncoding], "w+");

    int rsa_print = RSA_print_fp(tmpRSAFile, rsaKey, 0);
    fclose(tmpRSAFile);
    NSString * fileContents = [NSString stringWithContentsOfFile:tmpRSAFilePath encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"EMTG - RSA_print_fp:\n%@", fileContents);
    /////////////////

    NSString * tmpPEMFilePath = [NSTemporaryDirectory() stringByAppendingPathComponent: [NSString stringWithFormat: @"%.0f.%@", [NSDate timeIntervalSinceReferenceDate] * 1000.0, @"txt"]];
    FILE *tmpPEMFile = fopen([tmpPEMFilePath cStringUsingEncoding:NSUTF8StringEncoding], "w+");

    //int res_conversion = PEM_write_RSAPublicKey(tmpPEMFile, rsaKey);
    int res_conversion = PEM_write_RSA_PUBKEY(tmpPEMFile, rsaKey);

    fclose(tmpPEMFile);
    NSLog(@"EMTG - conversion result form RSA to PEM: %d", res_conversion);

    // read the contents into a string
    NSString *pemStr = [[NSString alloc]initWithContentsOfFile:tmpPEMFilePath encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"EMTG - PEM String content:\n%@", pemStr);
    
    NSString *pem1 = [pemStr componentsSeparatedByString:@"-----END PUBLIC KEY-----"][0];
    //NSLog(@"EMTG - PEM String content1:\n%@", pem1);
    NSString * pemResult = [pem1 componentsSeparatedByString:@"-----BEGIN PUBLIC KEY-----\n"][1];
    //NSLog(@"EMTG - PEM String result:\n%@", pemResult);

    ENGINE_finish(rsaEngine);
    RSA_free(rsaKey);

    return pemResult; //<-- exception of type NSException
    //return pemStr;
}

+(NSDictionary *) getJSONfronStringWithString:(NSString *) jsonString {
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    if (jsonData) {
        NSError *jsonError = nil;
        NSDictionary *jsonDic = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&jsonError];
        if (jsonDic) {
            return jsonDic;
        }
        NSLog(@"EMTG - Error in the JSON serialization from NSString to NSDictorionary: \n%@", jsonError);
        return nil;
    }
    return nil;
}

+(NSMutableDictionary *) getJWTPayloadDictionaryWithJWTDocument:(NSString *)jwtDocument {
    NSString *jwtDecoded = [self getJWTPayloadStringWithJWTDocument:jwtDocument];
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:jwtDecoded options:0];
    NSError *jsonError = nil;
    NSMutableDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:decodedData options:0 error:&jsonError];
    if (jsonDict) {
        return jsonDict;
    }

    NSLog(@"EMTG Error in the JSON payload docodification from JWT to NSDictorionary: \n%@", jsonError);
    return nil;
}

+(NSDictionary *) getHeaderDictioryFromJWTString:(NSString *) token {
    NSArray *tokenArray = [token componentsSeparatedByString:@"."];
    NSString *headerStr64url = [tokenArray objectAtIndex:0];
    NSString *headerStr64 = [MF_Base64Codec base64StringFromBase64UrlEncodedString:headerStr64url];
    //return [self getJSONfronStringWithString:headerStr64];
    return [self deserializationJSONObjectWithString:headerStr64];
}

+(NSString *) getJWTPayloadStringWithJWTDocument:(NSString *)jwtDocument {
    NSArray *payloadArray = [jwtDocument componentsSeparatedByString:@"."];
    NSString *payloadStr64url = [payloadArray objectAtIndex:1];
    return [MF_Base64Codec base64StringFromBase64UrlEncodedString:payloadStr64url];
}

+(NSString *) getJWTPayloadB64WithJWTDocument:(NSString *)jwtDocument {
    NSArray *payloadArray = [jwtDocument componentsSeparatedByString:@"."];
    NSString *payloadStr64url = [payloadArray objectAtIndex:1];
    return payloadStr64url;
}


+ (NSDictionary *) deserializationJSONObjectWithString:(NSString *)jsonString {
    NSError *jsonError = nil;
    NSData* payloadJsonData = [[NSData alloc]
                               initWithBase64EncodedString:jsonString
                               options:NSDataBase64DecodingIgnoreUnknownCharacters];
    //NSData *data = [jsonString dataUsingEncoding:NSUTF8StringEncoding];

    NSMutableDictionary *json = [NSJSONSerialization JSONObjectWithData:payloadJsonData options:0 error:&jsonError];
    //NSDictionary<NSString *, NSObject <NSCopying> *> *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonDeserializationError];
    if (jsonError) {
        // A problem occurred deserializing the JSON.
        NSError *returnedError = [OIDErrorUtilities errorWithCode:OIDErrorCodeJSONDeserializationError
                                                  underlyingError:jsonError
                                                  description:nil];
        NSLog(@"EMTG A problem occurred deserializing the JSON: \n%@", returnedError);
    }
    return json;
}

+(BOOL) isSubsetWithObj1:(id)obj1 obj2:(id)obj2 {

    if (![obj1 isKindOfClass:[obj2 class]])
        return NO;

    // Both objects have the same classtype
    if ([obj1 isKindOfClass:[NSString class]])
        return [obj1 isEqualToString:obj2];
    if ([obj1 isKindOfClass:[NSNumber class]])
        return ([obj1 longValue] <= [obj2 longValue]);
    //if ([obj1 isKindOfClass:[BOOL class]])
    if ([obj1 isKindOfClass:[NSArray class]]) {
        for (id o1 in obj1) {
            BOOL found = NO;
            for (id o2 in obj2) {
                if ([o1 isEqual:o2]) {
                    found = YES;
                    break;
                }
            }
            if (!found) {
                return NO;
            }
        }
        return YES;
    }
    if ([obj1 isKindOfClass:[NSDictionary class]]) {
        for (NSString* key1 in obj1) {
            id value1 = [obj1 objectForKey:key1];
            id value2 = [obj2 objectForKey:key1];
            
            if ((!value2) || (![self isSubsetWithObj1:value1 obj2:value2]))
                return NO;
        }
        return YES;
    }
    return NO;
}

+(NSDictionary *) flattenWithUpper:(NSDictionary *)upper lower:(NSDictionary *)lower {
    NSArray *use_lower = [NSMutableArray arrayWithObjects:@"iss", @"sub", @"aud", @"exp", @"nbf", @"iat", @"jti", nil];
    NSArray *use_upper = [NSMutableArray arrayWithObjects:@"signing_keys", @"signing_keys_uri", @"metadata_statement_uris", @"kid", @"metadata_statements", @"usage", nil];

    /* result starts as a copy of lower MS */
    NSMutableDictionary * flattened = [NSMutableDictionary dictionaryWithDictionary:lower];
    for (NSString * claim_name in [upper allKeys]) {
        if ([use_lower containsObject:claim_name])
            continue;

        /* If the claim does not exist on lower, or it is marked as "use_upper", or is a
         subset of lower, then use upper's one -> OK */
        // if (lower.opt(claim_name) == null || use_upper_list.contains(claim_name)|| isSubset(upper.get(claim_name), lower.get(claim_name))) {
        if (([lower objectForKey:claim_name] == nil)
              || [use_upper containsObject:claim_name]
              || [self isSubsetWithObj1:[upper objectForKey:claim_name] obj2:[lower objectForKey:claim_name]]) {
            [flattened setObject:[upper objectForKey:claim_name] forKey:claim_name];
        }
        else {
            /* Else -> policy breach */
            //TODO:  throw new InvalidStatementException("Policy breach with claim: " + claim_name + ". Lower value=" + lower.get(claim_name) + ". Upper value=" + upper.get(claim_name));
            flattened = nil;
            NSLog(@"EMTG - FLATTENED ERROR.");
            break;
        }
    }
    if (flattened)
        NSLog(@"EMTG - Flattened process completed.");

    return [NSDictionary dictionaryWithDictionary:flattened];;
}

+(NSDictionary *) getJWKDictionaryFromJWTPayloadString:(NSString *) jwtString {
    NSDictionary *payload = [self getJWTPayloadDictionaryWithJWTDocument:jwtString];
    NSDictionary *jwkDic = [payload objectForKey:@"signing_keys"];
    return jwkDic;
}

+ (BOOL) verifySignatureWithFed_ms_jwt:(NSString *)fed_ms_jwt validKeys:(NSDictionary *)validKeys {
    NSDictionary *header = [self getHeaderDictioryFromJWTString:fed_ms_jwt];
    NSString *payload = [self getJWTPayloadB64WithJWTDocument:fed_ms_jwt];
    //NSString *payload = [self getJWTPayloadStringWithJWTDocument:fed_ms_jwt];
    
    NSLog(@"EMTG - verifySignatureWithFed_ms_jwt - header: \n%@", header.debugDescription);

    NSString *kid = [header objectForKey:@"kid"];
    NSString *alg = [header objectForKey:@"alg"];
    NSString *algorithmName = @"RS256";

    NSLog(@"EMTG - print header params alg: %@ and kid: %@", alg, kid);

    //NSString *publicKey = nil;
    /*NSArray * keysArray = [validKeys objectForKey:@"keys"];
    for (NSDictionary *keyDic in keysArray) {
        NSString *value = [keyDic valueForKey:@"kid"];
        if ([value isEqualToString:kid]) {
            publicKey = [keyDic valueForKey:@"n"];
            NSLog(@"EMTG - public key found for kid: %@", kid);
        }
    }*/

    NSDictionary * publicKey = [validKeys valueForKey:kid];
    if (publicKey == nil) {
        NSLog(@"EMTG - ERROR: public key not found for kid: %@", kid);
        return NO;
    }
    NSLog(@"EMTG - public KEY FOUND for kid: %@", kid);

    NSString * pemPublicKey =  [self convertFromJWKtoPEM_PublicKey:publicKey];

    // extract keys
    //NSString *privateKey = ...;//extract from JWK dictionary and put them into appropriate key.
    
    NSDictionary *parameters = nil;     // pass nil parameters
    NSError *__autoreleasing*error = nil;

    /*id publicJWTKey = [[JWTCryptoKeyPublic alloc] initWithBase64String:pemPublicKey parameters:parameters error:error];
    //id publicJWTKey = [[JWTCryptoKeyPublic alloc] initWithPemEncoded:pemPublicKey parameters:parameters error:error]; // Uncaught exception of type NSException
    if (error == nil)
        NSLog(@"EMTG - error parsing the public key pem string:\n %@", error );
    else
        NSLog(@"EMTG - key extraction without errors.");*/
 
    id <JWTAlgorithmDataHolderProtocol> verifyDataHolder = [JWTAlgorithmRSFamilyDataHolder new].keyExtractorType([JWTCryptoKeyExtractor publicKeyWithPEMBase64].type).algorithmName(algorithmName).secret(pemPublicKey);

    JWTCodingBuilder *verifyBuilder = [JWTDecodingBuilder decodeMessage:fed_ms_jwt].addHolder(verifyDataHolder);
    
    NSLog(@"EMTG - token:\n%@\n\n", fed_ms_jwt);

    JWTCodingResultType *verifyResult = verifyBuilder.result;
    if (verifyResult.successResult) {
        // success
        NSLog(@"\n%@ success: %@", self.debugDescription, verifyResult.successResult.payload);
        payload = verifyResult.successResult.encoded;
        return YES;
    }
    else {
        // error
        NSLog(@"\n%@ error: %@", self.debugDescription, verifyResult.errorResult.error);
        return NO;
    }
    
    /*JWTBuilder *decodeBuilder = [JWTBuilder decodeMessage:fed_ms_jwt].secret(pemPublicKey).algorithmName(alg);
     NSDictionary *envelopedPayload = decodeBuilder.decode;
     
     NSLog(@"EMTG - decoded payload: %@", envelopedPayload.debugDescription);
     
     if (envelopedPayload != nil) {
     NSLog(@"EMTG - success");
     return YES;
     }
     NSLog(@"EMTG - error verifying signature");
     return NO;*/
    
}

+(NSString *) getMetadataStatementWithJSONDocument:(NSDictionary *)jsonDoc fed_OP:(NSString *) fed_OP {
    NSMutableDictionary *ms = [jsonDoc objectForKey:@"metadata_statements"];

    NSLog(@"EMTG - Decoding JWT of Federated Metadata Statement");
    if (ms != nil) {
        //NSDictionary  *ms_Dic = [self deserializationJSONObjectWithString:ms];
        NSString *ms_value = [ms objectForKey:fed_OP];
        if (ms_value != nil)
            //return [self getJWTPayloadStringWithJWTDocument:ms_value];
            return ms_value;
    }
    
    NSMutableDictionary *ms_uris = [jsonDoc objectForKey:@"metadata_statement_uris"];
    NSLog(@"EMTG - Decoding JWT of Federated Metadata Statement URIs");
    if (ms_uris != nil) {
        NSString *ms_uri_value = [ms_uris objectForKey:fed_OP];
        if (ms_uri_value != nil) {
            // Si no es nulo, recupero el documento de la URI
            NSURLRequest *request = [[NSURLRequest alloc] initWithURL:[NSURL URLWithString:ms_uri_value]];

            __block NSString *json;
            [NSURLConnection sendAsynchronousRequest:request
                                               queue:[NSOperationQueue mainQueue]
                                   completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
                                       //json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                                       //json = [self getJWTPayloadStringWithJWTDocument:[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]];
                                       json = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];

                                       NSLog(@"EMTG - Async JSON: %@", json);
                                   }];
            return json;
        }
    }
    return nil;
}

+(NSMutableDictionary *) addKeysFromArrayToDic:(NSMutableDictionary *)keyDict keyArray:(NSArray *) keyArray {

    if (keyDict == nil)
        keyDict = [[NSMutableDictionary alloc] init];

    //NSLog(@"EMTG - addKeysFromArrayToDic: debug array: \n%@", [keyArray debugDescription]);

    for (id item in keyArray) {
        NSDictionary * dic = item;
        [keyDict setObject:dic forKey:[dic valueForKey:@"kid"]];
    }

    NSLog(@"EMTG - addKeysFromArrayToDic: \n%@", [keyDict debugDescription]);
    return keyDict;
}

+(NSDictionary *) verifyMetadataStatementWithFed_ms_jwt:(NSString *)fed_ms_jwt
                                                 fed_OP:(NSString *)fed_op
                                               rootKeys:(NSDictionary *)rootKeys {

    //System.out.println("Inspecting MS signed by: " + payload.getString("iss") + " with KID:" + signedJWT.getHeader().getKeyID());

    NSMutableDictionary *keys = nil;
    NSString *payload_str = [self getJWTPayloadStringWithJWTDocument:fed_ms_jwt];
    NSDictionary *payload = [self deserializationJSONObjectWithString:payload_str];

    if (!payload) {
        NSLog(@"EMTG - ERROR extracting Metadata Statemente's payload.");
        return nil;
    }

    //NSLog(@"The payload is %@.", payload.debugDescription);
    NSLog(@"EMTG - Inspecting MS signed by %@.", [payload objectForKey:@"iss"]);

    /* Collect inner MS (JWT encoded) */
    NSString *inner_ms_jwt = [self getMetadataStatementWithJSONDocument:payload fed_OP:fed_op];

    /* This will hold the result of the verification/decoding/flattening */
    NSDictionary *result;

    /* If there are more MSs, recursively analyzed them and return the flattened version
     * with the inner payload */
    if (inner_ms_jwt != nil) {
        /* Recursion here to get a verified and flattened version of inner_ms */
        NSDictionary *inner_ms_flattened = [self verifyMetadataStatementWithFed_ms_jwt:inner_ms_jwt fed_OP:fed_op rootKeys:rootKeys];

        if (inner_ms_flattened) {
            /* add signing keys */
            // keys = JWKSet.parse(inner_ms_flattened.getJSONObject("signing_keys").toString()); <-- move after verification
            keys = [self addKeysFromArrayToDic:keys keyArray:[[inner_ms_flattened objectForKey:@"signing_keys"] objectForKey:@"keys"]];
            result = [self flattenWithUpper:payload lower:inner_ms_flattened];
        } else {
            NSLog(@"EMTG - verifyMetadataStatementWithFed_ms_jwt: Error at the flattened process");
            result = nil;
        }
    }
    /* If there are no inner metadata statements, this is MS0 and root keys must be used for
     * validating the signature. Result will be the decoded payload */
    else {
        //TODO: keys = JWKSet.parse(root_keys.getJSONObject(fed_op).toString());

        keys = [self addKeysFromArrayToDic:keys keyArray:[[rootKeys objectForKey:fed_op] objectForKey:@"keys"]];
        result = payload;
    }
    
    /* if the flattened process is completed (successfully) verify the signature using the collected keys */
    if (result) {
        NSLog(@"EMTG - Completed flattened process of fed_ms_st.");
    
        BOOL isVerified = [self verifySignatureWithFed_ms_jwt:fed_ms_jwt validKeys:keys];
        if (isVerified) {
            NSLog(@"EMTG - Successful validation of signature of %@ with KID.", [payload objectForKey:@"iss"]);
            return result;
        }
        else {
            NSLog(@"EMTG - Invalid signature of Metadata Statement");
            return nil;
        }
    }
    
    else
        NSLog(@"EMTG - ERROR in the Metadata Statement verification.");
        //TODO:with KID:" + signedJWT.getHeader().getKeyID());
    
    return result;
}


+(NSDictionary *) getFederatedConfigurationWithDiscoveryDocument:(NSDictionary *)discoveryDoc rootKeys:(NSDictionary *) rootKeys {
    //NSError *jsonError = nil;
    //NSDictionary *metadataStatement = [discoveryDoc objectForKey:@"metadata_statements"];
    //NSArray *fedetatedOPs = [metadataStatement allKeys];
    for (NSString* fed_op in rootKeys.allKeys) {
        NSLog(@"EMTG - Looking for a valid metada_statement for %@", fed_op);
        //NSLog(@"EMTG - Debuging received discovery document:\n%@", discoveryDoc);

        // TODO: String ms_jwt = getMetadataStatement(unsigned_ms, fed_op);

        NSString *fed_ms_jwt = [self getMetadataStatementWithJSONDocument:[discoveryDoc mutableCopy] fed_OP:fed_op];
        //NSLog(@"EMTG - getMetadataStatementWithJSONDocument: \n%@", fed_ms_jwt);
        
        if (fed_ms_jwt) {

            NSDictionary *ms_flattened = [self verifyMetadataStatementWithFed_ms_jwt:fed_ms_jwt
                                                                               fed_OP:fed_op
                                                                             rootKeys:rootKeys];
            //NSLog(@"EMTG - Statement for federation id %@", fed_op);
            //NSLog(@"%@", ms_flattened.debugDescription);
            return ms_flattened;
        }
    }
    return nil;
}
@end
