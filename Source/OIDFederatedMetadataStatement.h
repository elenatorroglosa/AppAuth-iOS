//
//  OIDFederatedMetadataStatement.h
//  AppAuth
//
//  Created by Elena Torroglosa on 19/11/17.
//  Copyright © 2017 OpenID Foundation. All rights reserved.
//

#ifndef OIDFederatedMetadataStatement_h
#define OIDFederatedMetadataStatement_h

#import <Foundation/Foundation.h>

@interface OIDFederatedMetadataStatement : NSObject

+(NSDictionary *) getJSONfronStringWithString:(NSString *) jsonString;

+(NSDictionary *) getJWTPayloadWithJWTDocument:(NSString *)jwtDocument;

/*! @internal
 @brief Unavailable. This class should not be initialized.
 */
//- (instancetype)init NS_UNAVAILABLE;

// private static boolean isSubset(Object obj1, Object obj2) throws JSONException
//+(BOOL) isSubsetWithObj1:(id)obj1 obj2:(id)obj2;

// private static JSONObject flatten(JSONObject upper, JSONObject lower) throws JSONException
// private static void verifySignature(SignedJWT signedJWT, JWKSet keys) throws BadJOSEException, JOSEException {
// private static String getMetadataStatement(JSONObject payload, String fed_op) throws IOException, JSONException
// private static JSONObject verifyMetadataStatement(String ms_jwt, String fed_op, JSONObject root_keys) throws JSONException, BadJOSEException, JOSEException, ParseException, IOException
// public static JSONObject getFederatedConfiguration(JSONObject discovery_doc, JSONObject root_keys) {

+(NSDictionary *) getFederatedConfigurationWithDiscoveryDocument:(NSDictionary *)discoveryDoc rootKeys:(NSDictionary *) rootKeys;

@end


#endif /* OIDFederatedMetadataStatement_h */
