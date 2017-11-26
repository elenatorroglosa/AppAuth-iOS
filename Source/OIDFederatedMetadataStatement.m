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

+(BOOL) isSubsetWithObj1:(id)obj1 obj2:(id)obj2 {
    
    
    /*
     
     if (!obj1.getClass().equals(obj2.getClass()))
     return false;
     else if (obj1 instanceof String)
     return obj1.equals(obj2);
     else if (obj1 instanceof Integer)
     return (Integer) obj1 <= (Integer) obj2;
     else if (obj1 instanceof Double)
     return (Double) obj1 <= (Double) obj2;
     else if (obj1 instanceof Long)
     return (Long) obj1 <= (Long) obj2;
     else if (obj1 instanceof Boolean)
     return obj1 == obj2;
     else if (obj1 instanceof JSONArray) {
     JSONArray list1 = (JSONArray) obj1;
     JSONArray list2 = (JSONArray) obj2;
     for (int i = 0; i < list1.length(); i++) {
     boolean found = false;
     for (int j = 0; j < list2.length(); j++) {
     if (list1.get(i).equals(list2.get(j))) {
     found = true;
     break;
     }
     }
     if (!found)
     return false;
     }
     return true;
     } else if (obj1 instanceof JSONObject) {
     JSONObject jobj1 = (JSONObject) obj1;
     JSONObject jobj2 = (JSONObject) obj2;
     for (Iterator<String> iter = jobj1.keys(); iter.hasNext(); ) {
     String key = iter.next();
     if (!jobj2.has(key) || !isSubset(jobj1.get(key), jobj2.get(key)))
     return false;
     }
     return true;
     }
     return false;

     */
    return NO;
}

+(NSDictionary *) flattenWithUpper:(NSDictionary *)upper lower:(NSDictionary *)lower {
    NSMutableArray *use_lower = [NSMutableArray arrayWithObjects:@"iss", @"sub", @"aud", @"exp", @"nbf", @"iat", @"jti", nil];
    NSMutableArray *use_upper = [NSMutableArray arrayWithObjects:@"signing_keys", @"signing_keys_uri", @"metadata_statement_uris", @"kid", @"metadata_statements", @"usage", nil];
    
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
        }
    }
    return flattened;
}

+(NSString *) getMetadataStatementWithJSONDocument:(NSDictionary *)discoveryDoc fed_OP:(NSString *) fed_OP {
    NSString *fed_ms_jwt = [discoveryDoc objectForKey:fed_OP];
    NSLog(@"EMTG Decoding JWT of Federated Metadata Statement");
    //NSDictionary  *ms_payload = [self getJWTPayloadWithJWTDocument:fed_ms_jwt];
    //TODO recover from metadata_statement_uris
    /*
     JSONObject ms_uris = payload.optJSONObject("metadata_statement_uris");
     if (ms != null && ms.has(fed_op))
     return ms.getString(fed_op);
     if (ms_uris != null && ms_uris.has(fed_op)) {
     System.out.println("Getting MS for " + fed_op + " from " + ms_uris.getString(fed_op));
     System.out.println(payload.toString());
     try {
     return IOUtils.toString(new URL(ms_uris.getString(fed_op)).openStream(), Charset.defaultCharset());
     } catch (IOException e) {
     throw new InvalidStatementException(e.getMessage());
     }
     }
     return null
     */
    /*
     NSString *algorithmName = @"RS256";
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
    
    return fed_ms_jwt;
}

+(NSDictionary *) verifyMetadataStatementWithFed_ms_jwt:(NSString *)fed_ms_jwt
                                                 fed_OP:(NSString *)fed_op
                                               rootKeys:(NSDictionary *)rootKeys {
    
    //System.out.println("Inspecting MS signed by: " + payload.getString("iss") + " with KID:" + signedJWT.getHeader().getKeyID());
    
    NSDictionary *payload = [self getJWTPayloadWithJWTDocument:fed_ms_jwt];
    NSLog(@"Inspecting MS signed by %@.", [payload objectForKey:@"iss"]);
    
    /* Collect inner MS (JWT encoded) */
    NSString *inner_ms_jwt = [self getMetadataStatementWithJSONDocument:payload fed_OP:fed_op];
    
    /* This will hold the result of the verification/decoding/flattening */
    NSDictionary *result;
    
    /* If there are more MSs, recursively analyzed them and return the flattened version
     * with the inner payload */
    if (inner_ms_jwt != nil) {
        /* Recursion here to get a verified and flattened version of inner_ms */
        //JSONObject inner_ms_flattened = verifyMetadataStatement(inner_ms_jwt, fed_op, root_keys);
        NSDictionary *inner_ms_flattened = [self verifyMetadataStatementWithFed_ms_jwt:inner_ms_jwt fed_OP:fed_op rootKeys:rootKeys];
        
        /* add signing keys */
        //TODO: JWKSet inner_ms_sigkeys = JWKSet.parse(inner_ms_flattened.getJSONObject("signing_keys").toString());
        //TODO: keys.getKeys().addAll(inner_ms_sigkeys.getKeys());
        result = [self flattenWithUpper:payload lower:inner_ms_flattened];
    }
    /* If there are no inner metadata statements, this is MS0 and root keys must be used for
     * validating the signature. Result will be the decoded payload */
    else {
        //TODO: keys = JWKSet.parse(root_keys.getJSONObject(fed_op).toString());
        result = payload;
    }
    
    /* verify the signature using the collected keys */
    //TODO verifySignature(signedJWT, keys);
    NSLog(@"Successful validation of signature of %@ with KID.", [payload objectForKey:@"iss"]);
        //TODO:with KID:" + signedJWT.getHeader().getKeyID());
    
    return result;
}


+(NSDictionary *) getFederatedConfigurationWithDiscoveryDocument:(NSDictionary *)discoveryDoc rootKeys:(NSDictionary *) rootKeys {
    
    NSError *jsonError = nil;

    NSDictionary *metadataStatement = [discoveryDoc objectForKey:@"metadata_statements"];
    //NSArray *fedetatedOPs = [metadataStatement allKeys];
    
    for (NSString* fed_op in rootKeys.allKeys) {
        NSLog(@"EMTG Looking for a valid metada_statement for %@", fed_op);
        
        // TODO: String ms_jwt = getMetadataStatement(unsigned_ms, fed_op);
        
        NSDictionary *fed_ms_jwt = [self getMetadataStatementWithJSONDocument:metadataStatement fed_OP:fed_op];
        NSLog(@"EMTG - fed_ms_jwt: \n%@", fed_ms_jwt);
        
        if (fed_ms_jwt) {
            
            NSDictionary  *ms_flattened = [self verifyMetadataStatementWithFed_ms_jwt:fed_ms_jwt
                                                                               fed_OP:fed_op
                                                                             rootKeys:rootKeys];
            NSLog(@"EMTG -  Statement for federation id %@", fed_op);
            NSLog(@"%@", ms_flattened.debugDescription);
            return ms_flattened;
        }
    }
    return nil;
}

@end
