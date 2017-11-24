//
//  OIDFederatedMetadataStatement.m
//  AppAuth
//
//  Created by Elena Torroglosa on 19/11/17.
//  Copyright © 2017 OpenID Foundation. All rights reserved.
//

#import "OIDFederatedMetadataStatement.h"
#import <JWT/JWT.h>
#import <JWT/JWTAlgorithmFactory.h>
#import <JWT/JWTClaimsSetSerializer.h>

#import <Base64/MF_Base64Additions.h>

//#import <JWT/JWTBuilder.h>
//#import <JWT/JWTAlgorithmFactory.h>
//#import <JWT/JWTAlgorithmDataHolder.h>
//#import <JWT/JWTAlgorithmRSBase.h>
//#import <JWT/JWTAlgorithmNone.h>
//#import <JWT/JWTRSAlgorithm.h>
//#import <JWT/JWTAlgorithmDataHolderChain.h>

@implementation OIDFederatedMetadataStatement


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

+(NSDictionary *) getJWTPayloadWithJWTDocument:(NSString *)jwtDocument {
    NSArray *payloadArray = [jwtDocument componentsSeparatedByString:@"."];
    NSString *payloadStr64 = [payloadArray objectAtIndex:1];
    payloadStr64 = [MF_Base64Codec base64StringFromBase64UrlEncodedString:payloadStr64];
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:payloadStr64 options:0];

    NSError *jsonError = nil;
    NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:decodedData options:0 error:&jsonError];
    if (jsonDict) {
        return jsonDict;
    }

    NSLog(@"EMTG Error in the JSON payload docodification from JWT to NSDictorionary: \n%@", jsonError);
    return nil;
}

+(NSDictionary *) getFederatedConfigurationWithDiscoveryDocument:(NSDictionary *)discoveryDoc rootKeys:(NSDictionary *) rootKeys {
    
    NSError *jsonError = nil;

    NSDictionary *metadataStatement = [discoveryDoc objectForKey:@"metadata_statements"];
    //NSArray *fedetatedOPs = [metadataStatement allKeys];
    
    for (NSString* fed_op in rootKeys.allKeys) {
        NSLog(@"EMTG Looking for a valid metada_statement for %@", fed_op);
        
        // TODO: String ms_jwt = getMetadataStatement(unsigned_ms, fed_op);
        
        NSString *fed_ms_jwt = [metadataStatement objectForKey:fed_op];
        NSLog(@"EMTG - fed_ms_jwt: \n%@", fed_ms_jwt);
        
        if (fed_ms_jwt) {
            NSLog(@"EMTG Decoding JWT of Federated Metadata Statement");
            
            NSDictionary  *ms_payload = [self getJWTPayloadWithJWTDocument:fed_ms_jwt];
            
            
            /*NSString *algorithmName = @"RS256";
            NSString *secret = @"secret";
            JWTClaimsSet *claimsSet = [[JWTClaimsSet alloc] init];
            claimsSet.subject = @"issuer";
            JWTClaimsSet *trustedClaimsSet = claimsSet.copy;
            trustedClaimsSet.expirationDate = [NSDate date];
            trustedClaimsSet.notBeforeDate = [NSDate date];
            trustedClaimsSet.issuedAt = [NSDate date];
            
            JWTBuilder *builder = [JWT decodeMessage:fed_ms_jwt].secret(secret).claimsSet(trustedClaimsSet).algorithmName(algorithmName);
            NSDictionary *info = builder.decode;
            
            NSLog(@"EMTG - info is: %@", info);
            NSLog(@"EMTG - error is: %@", builder.jwtError);
            
             */
        
            
            // JSONObject ms_flattened = verifyMetadataStatement(ms_jwt, fed_op, root_keys);
            
            return ms_payload;
        }
    }

    return nil;
}

@end
