//
//  OIDFederatedMetadataStatement.m
//  AppAuth
//
//  Created by Elena Torroglosa on 19/11/17.
//  Copyright © 2017 OpenID Foundation. All rights reserved.
//

#import "OIDFederatedMetadataStatement.h"

@implementation OIDFederatedMetadataStatement

+(NSDictionary *) getFederatedConfigurationWithDiscoveryDocument:(NSDictionary *)discoveryDoc rootKeys:(NSDictionary *) rootKeys {
    //NSDictionary *federatedConfiguration = discoveryDoc;

    NSDictionary *metadataStatement = [discoveryDoc objectForKey:@"metadata_statements"];

    return metadataStatement;
}

@end
