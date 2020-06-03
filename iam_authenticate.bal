import ballerina/http;
import ballerina/io;
import ballerina/log;
import ballerina/math;
import ballerina/stringutils;
import ballerina/time;
import ballerinax/java.jdbc;


import wso2/utils;

listener http:Listener IAM_AUTHENTICATOR = new (9090);
map<string> sessionMap = {};
map<boolean> authenticatedMap = {};
map<string> userMap = {"test1": "123", "test2": "456"};
string chatBuffer = "";
string pk = "";
string randomKey = "";

string ethereumAccount = "0x59Ce579B482E85B60d62676fFBbd1f7846F8393e";
string ethereumAccountPass = "1234";
http:Client ethereumClient = new ("http://127.0.0.1:8505");
jdbc:Client ssiDB = new ({
    url: "jdbc:mysql://localhost/ssidb",
    username: "root",
    password: "",
    dbOptions: {useSSL: false}
});

type DoctorCredential record {
    string doctorType;
    string name;
};




public function generateRandomKey(int keyLen) returns (string) {
    string buffer = "";
    int counter = 0;
    while (counter < keyLen) {
        int | error randVal = math:randomInRange(0, 26);
        int n = 0;
        if (randVal is int) {
            n = randVal;
        }

        buffer += utils:decToChar(65 + n);
        counter += 1;
    }
    io:println("generated Random key: " + buffer);
    return buffer;
}

public function getVerifiableCredentials(string didmid) returns @tainted string {
    io:println("verifying credentials");
    time:Time currentTime = time:currentTime();
    string | error timeStr = time:format(currentTime, "dd-MM-yyyy");
    string customTimeString = "";
    if (timeStr is string) {
        customTimeString = timeStr;
    }

    string doctorType = "";
    string firstname = "";
    var selectRet = ssiDB->select(<@untainted>"select doctorType, firstname from ssidb.govid where (did LIKE '" + <@untainted>didmid + "');", DoctorCredential);

    if (selectRet is table<DoctorCredential>) {
        if (selectRet.hasNext()) {
            var ret = selectRet.getNext();
            if (ret is DoctorCredential) {
                doctorType = ret.doctorType;
                firstname = ret.name;
            }
        }
    }

    string finalResult = sendTransactionAndgetHash(doctorType);

    string doctorCredential = "|||" + didmid + "," + finalResult + ",http://127.0.0.1:9090/api,DoctorCredential" + "||| " + "{" +
    "// set the context, which establishes the special terms we will be using" +
    "// such as 'issuer' and 'alumniOf'." +
    "\"@context\": [" +
    "  \"https://www.w3.org/2018/credentials/v1\"," +
    "  \"https://www.w3.org/2018/credentials/examples/v1\"" +
    "]," +
    "// specify the identifier for the credential" +
    "\"id\": \"http://localhost:9090/credentials/1\"," +
    "// the credential types, which declare what data to expect in the credential" +
    "\"type\": [\"VerifiableCredential\", \"DoctorCredential\"]," +
    "// the entity that issued the credential" +
    "\"issuer\": \"http://ip6-localhost:9090/api\"," +
    "// when the credential was issued" +
    "\"issuanceDate\": \"" + customTimeString + "\"," +
    "// claims about the subjects of the credential" +
    "\"credentialSubject\": {" +
    "// identifier for the only subject of the credential" +
    "\"id\": \"did:ethr:" + didmid + "\"," +
    "// assertion about the only subject of the credential" +
    "\"doctorType\": {" +
    " \"id\": \"did:ethr:" + finalResult + "\"," +
    "\"name\": [{" +
    "  \"value\": \"doctorType\"," +
    "\"lang\": \"en\"" +
    "}, {" +
    " \"value\": \"" + doctorType + "\"," +
    "\"lang\": \"en\"" +
    "}]" +
    "}" +
    "}," +
    "// digital proof that makes the credential tamper-evident" +
    "// see the NOTE at end of this section for more detail" +
    "\"proof\": {" +
    "// the cryptographic signature suite that was used to generate the signature" +
    "\"type\": \"RsaSignature2018\"," +
    "// the date the signature was created" +
    "\"created\": \"2017-06-18T21:19:10Z\"," +
    "// purpose of this proof" +
    "\"proofPurpose\": \"assertionMethod\"," +
    "// the identifier of the public key that can verify the signature" +
    "\"verificationMethod\": \"https://example.edu/issuers/keys/1\"," +
    "// the digital signature value" +
    "\"jws\": \"eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5X" +
    "sITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUc" +
    "X16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtj" +
    "PAYuNzVBAh4vGHSrQyHUdBBPM\"" +
    "}" +
    "}";


    return doctorCredential;
}

public function sendTransactionAndgetHash(string data) returns (string) {
    http:Request request2 = new;
    io:println("try to connect with eth acc");
    request2.setHeader("Content-Type", "application/json");
    request2.setJsonPayload({"jsonrpc": "2.0", "id": "2000", "method": "personal_unlockAccount", "params": [ethereumAccount, ethereumAccountPass, null]});

    string finalResult2 = "";
    boolean errorFlag2 = false;
    var httpResponse2 = ethereumClient->post("/", request2);
    io:println("eth request sends to 8081");
    if (httpResponse2 is http:Response) {
        int statusCode = httpResponse2.statusCode;
        string | error s = httpResponse2.getTextPayload();
        var jsonResponse = httpResponse2.getJsonPayload();

        if (jsonResponse is map<json>) {
            if (jsonResponse["error"] == null) {
                finalResult2 = jsonResponse.result.toString();
            } else {
                error err = error("EthereumError",
                message = "Error occurred while accessing the JSON payload of the response");
                finalResult2 = jsonResponse["error"].toString();
                errorFlag2 = true;
                log:printError("get hash err1: ", err = err);
            }
        } else {
            error err = error("EthereumError", message = "Error occurred while accessing the JSON payload of the response");
            finalResult2 = "Error occurred while accessing the JSON payload of the response";
            errorFlag2 = true;
            log:printError("get hash err2: ", err = err);
        }
    } else {
        error err = error("EthereumError", message = "Error occurred while invoking the Ethererum API");
        errorFlag2 = true;
        log:printError("get hash err2: ", err = err);
    }
    io:println("no problem get acc 8081");
    string hexEncodedString = "0x" + utils:hashSHA256(data);

    //Next we will write the blockchain record
    http:Request request = new;
    request.setHeader("Content-Type", "application/json");
    request.setJsonPayload({"jsonrpc": "2.0", "id": "2000", "method": "eth_sendTransaction", "params": [{"from": ethereumAccount, "to": "0x6814412628addef8989ee696a67b0fad5d62735e", "data": hexEncodedString}]});
    io:println("eth write blockchain record 8081");
    string finalResult = "";
    boolean errorFlag = false;
    var httpResponse = ethereumClient->post("/", request);

    if (httpResponse is http:Response) {
        int statusCode = httpResponse.statusCode;
        var jsonResponse = httpResponse.getJsonPayload();
        if (jsonResponse is map<json>) {
            if (jsonResponse["error"] == null) {
                finalResult = jsonResponse.result.toString();
            } else {
                error err = error("EthereumError", message = "Error occurred while accessing the JSON payload of the response");
                finalResult = jsonResponse["error"].toString();
                errorFlag = true;
                log:printError("get hash err4: ", err = err);
            }
        } else {
            error err = error("EthereumError", message = "Error occurred while accessing the JSON payload of the response");
            finalResult = "Error occurred while accessing the JSON payload of the response";
            errorFlag = true;
            log:printError("get hash err5: ", err = err);
        }
    } else {
        error err = error("EthereumError", message = "Error occurred while invoking the Ethererum API");
        errorFlag = true;
        log:printError("get hash err6: ", err = err);
    }
    io:println("all good???");
    return finalResult;
}

service uiServiceIAM_AUTHENTICATOR on IAM_AUTHENTICATOR {
    @http:ResourceConfig {
        methods: ["GET"],
        path: "/",
        cors: {
            allowOrigins: ["*"],
            allowHeaders: ["Authorization, Lang"]
        }
    }
    resource function displayRegisterPage(http:Caller caller, http:Request req) {
        string buffer = readFile("register.html");
        http:Response res = new;

        if (caller.localAddress.host != "") {
            buffer = stringutils:replace(buffer, "127.0.0.1", caller.localAddress.host);
        }
        res.setPayload(<@untainted>buffer);
        res.setContentType("text/html; charset=utf-8");
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE");
        res.setHeader("Access-Control-Allow-Headers", "Authorization, Lang");

        var result = caller->respond(res);
        if (result is error) {
            log:printError("Error sending response", err = result);
        }
    }



    @http:ResourceConfig {
        methods: ["POST"],
        path: "/api",
        cors: {
            allowOrigins: ["*"],
            allowHeaders: ["Authorization, Lang"]
        }
    }
    resource function api(http:Caller caller, http:Request req) returns error? {
        var requestVariableMap = check req.getFormParams();

        if (requestVariableMap["command"] == "cmd1") {
            io:println("inside cmd1");
            if (requestVariableMap.hasKey("secureToken") && (!stringutils:equalsIgnoreCase(randomKey, requestVariableMap["secureToken"] ?: ""))) {
                io:println("incorrect sec token");
                var result = caller->respond("incorrect-token");

                if (result is error) {
                    log:printError("Error sending response", err = result);
                }
            } else {
                if (requestVariableMap.hasKey("did")) {
                    pk = <@untainted>requestVariableMap["did"] ?: "";
                    io:println("pk :" + pk);
                    var result = caller->respond("done");

                    if (result is error) {
                        log:printError("Error sending response", err = result);
                    }
                }
            }
        } else if (requestVariableMap["command"] == "requestvc") {
            io:println("insdie requestvc");
            string didxx = requestVariableMap["did"] ?: "didx";
            io:println("did api reqvc: " + didxx);
            var did = requestVariableMap["did"] ?: "";
            did = stringutils:replace(did, "%2C", ",");
            did = utils:binaryStringToString(did);

            int index2 = (did.indexOf("\"id\": \"did:ethr:") ?: 0) + 16;
            string didmid = did.substring(index2, index2 + 64);
            io:println("didmid api reqvc: " + didmid);
            index2 = (did.indexOf("-----BEGIN PUBLIC KEY-----") ?: 0) + 26;

            int index3 = did.indexOf("-----END PUBLIC KEY-----") ?: 0;
            var publicKey = did.substring(index2, index3);

            didmid = "0x" + didmid;
            http:Request request = new;
            request.setHeader("Content-Type", "application/json");
            request.setJsonPayload({"jsonrpc": "2.0", "id": "2000", "method": "eth_getTransactionByHash", "params": [<@untainted>didmid]});

            string finalResult = "";
            string pkHash = "";
            boolean errorFlag = false;
            io:println("is going to 8081??");
            var httpResponse = ethereumClient->post("/", request);
            if (httpResponse is http:Response) {
                int statusCode = httpResponse.statusCode;
                var jsonResponse = httpResponse.getJsonPayload();
                if (jsonResponse is map<json>) {
                    if (jsonResponse["error"] == null) {
                        pkHash = jsonResponse.result.input.toString();
                    } else {
                        error err = error("(wso2/ethereum)EthereumError", message = "Error occurred while accessing the JSON payload of the response");
                        finalResult = jsonResponse["error"].toString();
                        errorFlag = true;
                        log:printError("requesvc err1", err = err);
                    }
                } else {
                    error err = error("(wso2/ethereum)EthereumError", message = "Error occurred while accessing the JSON payload of the response");
                    finalResult = "Error occurred while accessing the JSON payload of the response";
                    errorFlag = true;
                    log:printError("requesvc err2", err = err);
                }
            } else {
                error err = error("(wso2/ethereum)EthereumError", message = "Error occurred while invoking the Ethererum API");
                errorFlag = true;
                log:printError("requesvc err3", err = err);
            }

            string hexEncodedString = "0x" + utils:hashSHA256("-----BEGIN PUBLIC KEY-----" + publicKey + "-----END PUBLIC KEY-----");

            if (hexEncodedString == pkHash) {
                string randKey = generateRandomKey(16);
                sessionMap[didmid] = randKey;
                finalResult = utils:encryptRSAWithPublicKey(publicKey, randKey);
                io:println("success key validadtion");
            } else {
                finalResult = "Failure in Key Verification";
                io:println("key validation failed");
            }

            http:Response res = new;
            // A util method that can be used to set string payload.
            io:println("final result key validation: " + finalResult);
            res.setPayload(<@untainted>finalResult);
            res.setContentType("text/html; charset=utf-8");
            res.setHeader("Access-Control-Allow-Origin", "*");
            res.setHeader("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE");
            res.setHeader("Access-Control-Allow-Headers", "Authorization, Lang");

            // Sends the response back to the client.
            var result = caller->respond(res);
            if (result is error) {
                log:printError("Error sending response", err = result);
            }
            io:println("send key response successfully");
        } else if (requestVariableMap["command"] == "encresponse") {
            var did = requestVariableMap["did"] ?: "";
            string didxx = requestVariableMap["did"] ?: "didx";
            io:println("encresponse did: " + didxx);
            var encryptedval = requestVariableMap["encryptedval"] ?: "";

            did = stringutils:replace(did, "%2C", ",");
            did = utils:binaryStringToString(did);

            int index2 = (did.indexOf("\"id\": \"did:ethr:") ?: 0) + 16;
            string didmid = did.substring(index2, index2 + 64);

            index2 = (did.indexOf("-----BEGIN PUBLIC KEY-----") ?: 0) + 26;
            io:println("index2" + index2.toString());
            int index3 = did.indexOf("-----END PUBLIC KEY-----") ?: 0;
            var publicKey = did.substring(index2, index3);
            var didmidOrg = didmid;
            didmid = "0x" + didmid;

            string randKey = sessionMap[didmid] ?: "";

            if (encryptedval === randKey) {
                io:println(encryptedval.toString() + randKey.toString() + didmidOrg.toString());
                var verifiableCredentialsList = getVerifiableCredentials(didmidOrg);

                http:Response res = new;
                // A util method that can be used to set string payload.
                res.setPayload(<@untainted>verifiableCredentialsList);
                res.setContentType("text/html; charset=utf-8");
                res.setHeader("Access-Control-Allow-Origin", "*");
                res.setHeader("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE");
                res.setHeader("Access-Control-Allow-Headers", "Authorization, Lang");

                // Sends the response back to the client.
                var result = caller->respond(res);
                io:println("enc response sends....");
                if (result is error) {
                    log:printError("Error sending response", err = result);
                }
            } else {
                io:println("Challenge response authentication failed.");
            }
        }
    }

}
