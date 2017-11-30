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
//#import <JWT/JWTAlgorithmFactory.h>
//#import <JWT/JWTAlgorithmDataHolder.h>
//#import <JWT/JWTAlgorithmRSBase.h>
//#import <JWT/JWTAlgorithmNone.h>
//#import <JWT/JWTRSAlgorithm.h>
//#import <JWT/JWTAlgorithmDataHolderChain.h>

@implementation OIDFederatedMetadataStatement


+(NSMutableDictionary *) getJSONfronStringWithString:(NSString *) jsonString {
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    if (jsonData) {
        NSError *jsonError = nil;
        NSMutableDictionary *jsonDic = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&jsonError];
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

+(NSString *) getJWTPayloadStringWithJWTDocument:(NSString *)jwtDocument {
    NSArray *payloadArray = [jwtDocument componentsSeparatedByString:@"."];
    NSString *payloadStr64url = [payloadArray objectAtIndex:1];
    return [MF_Base64Codec base64StringFromBase64UrlEncodedString:payloadStr64url];
}

+ (NSMutableDictionary *) deserializationJSONObjectWithString:(NSString *)jsonString {
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

+(NSMutableDictionary *) flattenWithUpper:(NSMutableDictionary *)upper lower:(NSMutableDictionary *)lower {
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
            flattened = nil;
            NSLog(@"EMTG - FLATTENED ERROR.");
            break;
        }
    }
    if (flattened)
        NSLog(@"EMTG - Flattened process completed.");

    return flattened;
}

//getMetadataStatementWithJWTDocument



+(NSString *) getMetadataStatementWithJSONDocument:(NSDictionary *)jsonDoc fed_OP:(NSString *) fed_OP {
    NSMutableDictionary *ms = [jsonDoc objectForKey:@"metadata_statements"];
    
    NSLog(@"EMTG - Decoding JWT of Federated Metadata Statement");
    if (ms != nil) {
        //NSDictionary  *ms_Dic = [self deserializationJSONObjectWithString:ms];
        NSString *ms_value = [ms objectForKey:fed_OP];
        if (ms_value != nil)
            return [self getJWTPayloadStringWithJWTDocument:ms_value];
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
                                       json = [self getJWTPayloadStringWithJWTDocument:[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]];
                                       NSLog(@"EMTG - Async JSON: %@", json);
                                   }];
            
            return json;
        }
    }
    return nil;
}

+(NSMutableDictionary *) verifyMetadataStatementWithFed_ms_jwt:(NSString *)fed_ms_jwt
                                                 fed_OP:(NSString *)fed_op
                                               rootKeys:(NSDictionary *)rootKeys {
    
    //System.out.println("Inspecting MS signed by: " + payload.getString("iss") + " with KID:" + signedJWT.getHeader().getKeyID());
    
    //NSDictionary *payload = [self getJWTPayloadDictionaryWithJWTDocument:fed_ms_jwt];
    NSMutableDictionary *payload = [self deserializationJSONObjectWithString:fed_ms_jwt];
    if (!payload)
        return nil;
    
    //NSLog(@"The payload is %@.", payload.debugDescription);
    NSLog(@"Inspecting MS signed by %@.", [payload objectForKey:@"iss"]);
    
    /* Collect inner MS (JWT encoded) */
    NSString *inner_ms_jwt = [self getMetadataStatementWithJSONDocument:payload fed_OP:fed_op];
    
    /* This will hold the result of the verification/decoding/flattening */
    NSMutableDictionary *result;
    
    /* If there are more MSs, recursively analyzed them and return the flattened version
     * with the inner payload */
    if (inner_ms_jwt != nil) {
        /* Recursion here to get a verified and flattened version of inner_ms */
        //JSONObject inner_ms_flattened = verifyMetadataStatement(inner_ms_jwt, fed_op, root_keys);
        NSMutableDictionary *inner_ms_flattened = [self verifyMetadataStatementWithFed_ms_jwt:inner_ms_jwt fed_OP:fed_op rootKeys:rootKeys];
        
        if (inner_ms_flattened) {
            /* add signing keys */
            //TODO: JWKSet inner_ms_sigkeys = JWKSet.parse(inner_ms_flattened.getJSONObject("signing_keys").toString());
            //TODO: keys.getKeys().addAll(inner_ms_sigkeys.getKeys());
            result = [self flattenWithUpper:payload lower:inner_ms_flattened];
        } else {
            result = nil;
        }
    }
    /* If there are no inner metadata statements, this is MS0 and root keys must be used for
     * validating the signature. Result will be the decoded payload */
    else {
        //TODO: keys = JWKSet.parse(root_keys.getJSONObject(fed_op).toString());
        result = payload;
    }
    
    /* verify the signature using the collected keys */
    //TODO verifySignature(signedJWT, keys);

    if (result)
        NSLog(@"Successful validation of signature of %@ with KID.", [payload objectForKey:@"iss"]);
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
        NSLog(@"EMTG Looking for a valid metada_statement for %@", fed_op);
        
        // TODO: String ms_jwt = getMetadataStatement(unsigned_ms, fed_op);
        
        NSString *fed_ms_jwt = [self getMetadataStatementWithJSONDocument:[discoveryDoc mutableCopy] fed_OP:fed_op];
        //NSLog(@"EMTG - getMetadataStatementWithJSONDocument: \n%@", fed_ms_jwt);
        
        if (fed_ms_jwt) {
            
            NSMutableDictionary *ms_flattened = [self verifyMetadataStatementWithFed_ms_jwt:fed_ms_jwt
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
