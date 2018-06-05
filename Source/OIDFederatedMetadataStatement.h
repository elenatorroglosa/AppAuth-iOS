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

+(NSMutableDictionary *) getJSONfronStringWithString:(NSString *) jsonString;

+(NSMutableDictionary *) getJWTPayloadDictionaryWithJWTDocument:(NSString *)jwtDocument;

+(NSString *) getJWTPayloadStringWithJWTDocument:(NSString *)jwtDocument;

/*! @internal
 @brief Unavailable. This class should not be initialized.
 */
//- (instancetype)init NS_UNAVAILABLE;

// private static boolean isSubset(Object obj1, Object obj2) throws JSONException
//+ (BOOL) isSubsetWithObj1:(id)obj1 obj2:(id)obj2;

// private static JSONObject flatten(JSONObject upper, JSONObject lower) throws JSONException

// private static void verifySignature(SignedJWT signedJWT, JWKSet keys) throws BadJOSEException, JOSEException {
// -- private static String getMetadataStatement(JSONObject payload, String fed_op) throws IOException, JSONException
// -- private static JSONObject verifyMetadataStatement(String ms_jwt, String fed_op, JSONObject root_keys) throws JSONException, BadJOSEException, JOSEException, ParseException, IOException
// ++ public static JSONObject getFederatedConfiguration(JSONObject discovery_doc, JSONObject root_keys) {

/**
 * @brief Indicates whether an object is a subset of another one, according to the OIDC Federation draft.
 * @param obj1 One object.
 * @param obj2 Another object.
 * @return YES if obj1 is a subset of obj2. NO otherwise.
 */
+(BOOL) isSubsetWithObj1:(id)obj1 obj2:(id)obj2;

/**
 * @brief Flatten two metadata statements into one, following the rules from the OIDC federation draft.
 * @param upper MS(n)
 * @param lower MS(n-1)
 * @return A flattened version of both statements.
 * //@throws InvalidStatementException when there is a policy break and upper MS tries to overwrite lower MS
 *                                   breaking the policies from the OIDC federation draft.
 */
+(NSDictionary *) flattenWithUpper:(NSDictionary *)upper lower:(NSDictionary *)lower;

/**
 * @brief Decodes, verifies and flattens a compounded MS for a specific federation operator
 * @param fed_ms_jwt    Encoded JWT representing a signed metadata statement
 * @param fed_op    Name of the Federator Operator
 * @param rootKeys  Collection of JWSK of the accepted FO
 * @return A flattened and verified MS
 */
+(NSDictionary *) verifyMetadataStatementWithFed_ms_jwt:(NSString *)fed_ms_jwt
                                                 fed_OP:(NSString *)fed_op
                                               rootKeys:(NSDictionary *)rootKeys;

+(NSString *) getMetadataStatementWithJSONDocument:(NSDictionary *)discoveryDoc fed_OP:(NSString *) fed_OP;

+(NSDictionary *) getFederatedConfigurationWithDiscoveryDocument:(NSDictionary *)discoveryDoc rootKeys:(NSDictionary *) rootKeys;

+ (NSDictionary *) genFederatedConfigurationUnsigned_ms:(NSDictionary *)unsigned_ms
                                                    sms:(NSDictionary *)sms
                                           signing_keys:(NSDictionary *)signing_keys
                                                    iss:(NSString *) iss;

@end


#endif /* OIDFederatedMetadataStatement_h */
