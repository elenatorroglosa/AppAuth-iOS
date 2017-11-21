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
            
            //id<JWTAlgorithm> algorithm = [JWTAlgorithmFactory  algorithmByName:@"RS256"];
            
            JWTBuilder *builder = [JWTBuilder decodeMessage:fed_ms_jwt].secret(@"secret").algorithmName(@"RS256");
            NSDictionary *info = builder.decode;
            
            NSLog(@"EMTG - info is: %@", info);
            NSLog(@"EMTG - error is: %@", builder.jwtError);
            
            /*NSString *firstSecret = @"first";
            NSString *firstAlgorithmName = JWTAlgorithmNameRS256;
            
            id <JWTAlgorithmDataHolderProtocol> firstHolder = [JWTAlgorithmHSFamilyDataHolder new].algorithmName(firstAlgorithmName).secret(firstSecret);
            
            id <JWTAlgorithmDataHolderProtocol> errorHolder = [JWTAlgorithmNoneDataHolder new];
            
            // chain together.
            JWTAlgorithmDataHolderChain *chain = [[JWTAlgorithmDataHolderChain alloc] initWithHolders:@[firstHolder, errorHolder]];
*/
            
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
            
            //[[@(noError) should] equal:@(YES)];
             */
            
            
        
            //NSString *payload_str = payload.debugDescription;
            //NSLog(@"EMTG - metadata_statementt: \n%@", payload_str);
            
            // JSONObject ms_flattened = verifyMetadataStatement(ms_jwt, fed_op, root_keys);
            
            
            return info;
        }
    }

    return nil;
}

@end
