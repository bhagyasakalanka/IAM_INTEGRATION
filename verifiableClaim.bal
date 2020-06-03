import ballerina/crypto;
import ballerina/file;
import ballerina/http;
import ballerina/io;
import ballerina/log;
import ballerina/runtime;
import ballerina/stringutils;
import ballerinax/java.jdbc;
import wso2/utils;

listener http:Listener uiHolderLogin = new (9091);

map<string> sessionMap = {};
map<boolean> authenticatedMap = {};
map<string> userMap = {"test1": "123"};
string chatBuffer = "";
string pk = "";
string verifiableCredentialsRepositoryURL = "https://127.0.0.1:9091/vc/";
string ethereumAccount = "0x59Ce579B482E85B60d62676fFBbd1f7846F8393e";
string ethereumAccountPass = "1234";

http:Client ethereumClient = new ("http://127.0.0.1:8504");

jdbc:Client ssiDB = new ({
    url: "jdbc:mysql://127.0.0.1:3306/ssidb",
    username: "root",
    password: "",
    dbOptions: {useSSL: false}
});

type HolderRecord record {
    string id;
    string issuer;
    string name;
};

type VCRecord record {
    string vctxt;
};

type FullVCRecord record {
    string id;
    string issuer;
    string name;
};

type NameRecord record {
    string name;
};

string holderRepo = "test1";

@http:ServiceConfig {
    basePath: "/",
    cors: {
        allowOrigins: ["*"],
        allowHeaders: ["Authorization, Lang"]
    }
}
service uiServiceVerifiableClaim on VerifiableClaim {
    @http:ResourceConfig {
        methods: ["GET"],
        path: "/",
        cors: {
            allowOrigins: ["*"],
            allowHeaders: ["Authorization, Lang"]
        }
    }
    resource function displayLoginPage(http:Caller caller, http:Request req) {
        string buffer = readFile("verifable_claim.html");

        http:Response res = new;

        if (caller.localAddress.host != "") {
            buffer = stringutils:replace(buffer, "localhost", caller.localAddress.host);
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
        path: "/authenticate",
        cors: {
            allowOrigins: ["*"],
            allowHeaders: ["Authorization, Lang"]
        }
    }
    resource function processLogin(http:Caller caller, http:Request req) returns error? {
        var requestVariableMap = check req.getFormParams();
        string username = requestVariableMap["username"] ?: "";
        string password = requestVariableMap["pwd"] ?: "";
        var authenticated = false;

        foreach var [k, v] in userMap.entries() {
            if (stringutils:equalsIgnoreCase(username, k) && stringutils:equalsIgnoreCase(password, v)) {
                authenticatedMap[username] = true;
                var result = caller->respond("success");
                if (result is error) {
                    log:printError("Error sending response", err = result);
                } else {
                    authenticated = true;
                }
                break;
            }
        }

        if (!authenticated) {
            var result = caller->respond("failed");
            if (result is error) {
                log:printError("Error sending response", err = result);
            }
        }

        return;
    }


    @http:ResourceConfig {
        methods: ["POST"],
        path: "/vc",
        cors: {
            allowOrigins: ["*"],
            allowHeaders: ["Authorization, Lang"]
        }
    }
    resource function listVC(http:Caller caller, http:Request req) returns error? {
        map<string> requestVariableMap = check req.getFormParams();
        string did = requestVariableMap["did"] ?: "";
        var selectRet = ssiDB->select(<@untainted>"select id, issuer, name from ssidb.vclist where (did LIKE '" + <@untainted>did + "');", FullVCRecord);
        string tbl = "<table><tr><td>No Verifiable credentials associated with your account yet.";

        if (selectRet is table<FullVCRecord>) {

            if (!selectRet.hasNext()) {
                tbl = "<table border=\"1px\" cellspacing=\"0\" cellpadding=\"3\"><tr><td>No Verifiable Credentials found for this DID</td></tr></table>";
            } else {
                tbl = "<table border=\"1px\" cellspacing=\"0\" cellpadding=\"3\"><tr><th>Verifiable Cerdential's DID</th><th>Name</th><th>Issuer</th><th>&nbsp;</th></tr>";
                while (selectRet.hasNext()) {
                    var ret = selectRet.getNext();
                    if (ret is FullVCRecord) {
                        tbl = tbl + "<tr><td><a href=\"#\" onclick=\"showVC('" + ret.id.toString() + "');\">";
                        tbl = tbl + ret.id.toString();
                        tbl = tbl + "</a></td><td>";
                        tbl = tbl + ret.name;
                        tbl = tbl + "</td><td>";
                        tbl = tbl + ret.issuer;
                        tbl = tbl + "</td><td><input type=\"checkbox\" id=\"" + ret.id.toString() + "\" name=\"vcselect\"\\>";
                    } else {
                        io:println("Error in get HolderRecord from table");
                    }
                }
                tbl += "</td></tr></table><br/><input id=\"vc-btn\" type=\"button\" value=\"Submit VC\" onclick=\"submitVC()\">";
            }
        } else {
            io:println("Select data from vclist table failed");
        }

        http:Response res = new;
        var buffer = tbl;

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

        string publicKey = requestVariableMap["publickey"] ?: "";
        publicKey = stringutils:replace(publicKey, "+", " ");
        publicKey = stringutils:replace(publicKey, "%2B", "+");
        publicKey = stringutils:replace(publicKey, "%2F", "/");
        publicKey = stringutils:replace(publicKey, "%3D", "=");

        if (requestVariableMap["command"] == "cmd1") {
            string finalResult = sendTransactionAndgetHash(publicKey);

            if (finalResult == "-1") {
                //If its error
                io:println("its is null--->" + finalResult);
                http:Response res = new;
                res.setPayload(<@untainted>"null");
                res.setContentType("text/html; charset=utf-8");
                res.setHeader("Access-Control-Allow-Origin", "*");
                res.setHeader("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE");
                res.setHeader("Access-Control-Allow-Headers", "Authorization, Lang");

                var result = caller->respond(res);
                if (result is error) {
                    log:printError("Error sending response", err = result);
                }
            } else {
                finalResult = finalResult.substring(2, 66);

                var templateDID = "{" +
                "\"@context\": \"https://w3id.org/did/v1\"," +
                "\"id\": \"did:ethr:" + finalResult + "\"," +
                "\"authentication\": [{" +
                // used to authenticate as did:...fghi
                "\"id\": \"did:ethr:" + finalResult + "#keys-1\"," +
                "\"type\": \"RsaVerificationKey2018\"," +
                "\"controller\": \"did:ethr:" + finalResult + "\"," +
                "\"publicKeyPem\": \"" + publicKey + "\"" +
                "}]," +
                "\"service\": [{" +
                // used to retrieve Verifiable Credentials associated with the DID
                "\"type\": \"VerifiableCredentialService\"," +
                "\"serviceEndpoint\": \"" + verifiableCredentialsRepositoryURL + "\"" +
                "}]" +
                "}";

                io:println(templateDID);

                string path = holderRepo + "/did.json";

                io:WritableByteChannel wbc = check io:openWritableFile(path);

                io:WritableCharacterChannel wch = new (wbc, "UTF8");
                var wResult = wch.writeJson(templateDID);
                closeWc(wch);

                if (wResult is error) {
                    log:printError("Error occurred while writing json: ", err = wResult);
                }

                http:Response res = new;
                res.setPayload(<@untainted>templateDID);
                res.setContentType("text/html; charset=utf-8");
                res.setHeader("Access-Control-Allow-Origin", "*");
                res.setHeader("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE");
                res.setHeader("Access-Control-Allow-Headers", "Authorization, Lang");

                var result = caller->respond(res);
                if (result is error) {
                    log:printError("Error sending response", err = result);
                }
            }
        } else if (requestVariableMap["command"] == "cmd2") {
            string did = requestVariableMap["did"] ?: "";
            string didVC = requestVariableMap["didVC"] ?: "";
            string issuerVC = requestVariableMap["issuerVC"] ?: "";
            string nameVC = requestVariableMap["nameVC"] ?: "";
            string vcTxt = requestVariableMap["vcTxt"] ?: "";
            var selectRet = ssiDB->select(<@untainted>"select name from ssidb.vclist where (did LIKE '" + <@untainted>did + "');", NameRecord);

            string name2 = "";

            if (selectRet is table<NameRecord>) {
                if (selectRet.hasNext()) {
                    var jsonConversionRet = selectRet.getNext();

                    if (jsonConversionRet is NameRecord) {
                        name2 = jsonConversionRet.name;

                        if (nameVC === name2) {
                            http:Response res = new;
                            res.setPayload(<@untainted>"vc-already-exist");
                            res.setContentType("text/html; charset=utf-8");
                            res.setHeader("Access-Control-Allow-Origin", "*");
                            res.setHeader("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE");
                            res.setHeader("Access-Control-Allow-Headers", "Authorization, Lang");

                            var result = caller->respond(res);
                            if (result is error) {
                                log:printError("Error sending response", err = result);
                            }

                            return;
                        }
                    }
                } else {
                //The result is empty
                }
            }

            vcTxt = stringutils:replace(vcTxt, "'", "''");
            var ret = ssiDB->update(<@untainted>("insert into ssidb.vclist(did, id, issuer, name, vctext) " + "values ('" + did + "', '" + didVC.substring(2, didVC.length()) + "', '" + issuerVC + "', '" + nameVC + "', '" + vcTxt + "');"));

            var selectRet2 = ssiDB->select(<@untainted>"select id, issuer, name from ssidb.vclist where (did LIKE '" + <@untainted>did + "');", HolderRecord);
            string tbl = "<table><tr><td>No Verifiable credentials associated with your account yet.";

            if (selectRet2 is table<HolderRecord>) {
                if (!selectRet2.hasNext()) {
                    tbl = "<table border=\"1px\" cellspacing=\"0\" cellpadding=\"3\"><tr><td>No Verifiable Credentials found for this DID</td></tr></table>";
                } else {
                    tbl = "<table border=\"1px\" cellspacing=\"0\" cellpadding=\"3\"><tr><th>Verifiable Cerdential's DID</th><th>Name</th><th>Issuer</th></tr>";

                    while (selectRet2.hasNext()) {
                        var ret2 = selectRet2.getNext();
                        if (ret2 is HolderRecord) {
                            tbl = tbl + "<tr><td>";
                            tbl = tbl + ret2.id;
                            tbl = tbl + "</td><td>";
                            tbl = tbl + ret2.name;
                            tbl = tbl + "</td><td>";
                            tbl = tbl + ret2.issuer;
                        } else {
                            io:println("Error in get HolderRecord from table");
                        }
                    }
                    tbl += "</td></tr></table>";
                }
            } else {
                io:println("Select data from vclist table failed");
            }

            http:Response res = new;
            res.setPayload(<@untainted>tbl);
            res.setContentType("text/html; charset=utf-8");
            res.setHeader("Access-Control-Allow-Origin", "*");
            res.setHeader("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE");
            res.setHeader("Access-Control-Allow-Headers", "Authorization, Lang");

            var result = caller->respond(res);
            if (result is error) {
                log:printError("Error sending response", err = result);
            }
        } else if (requestVariableMap["command"] == "cmd3") {
            string id = requestVariableMap["id"] ?: "";
            var selectRet = ssiDB->select(<@untainted>"select vctext from ssidb.vclist where (id LIKE '" + <@untainted>id + "');", VCRecord);

            string vcText = "no-vc-for-this-did";

            if (selectRet is table<VCRecord>) {
                if (selectRet.hasNext()) {
                    var ret2 = selectRet.getNext();
                    if (ret2 is VCRecord) {
                        vcText = ret2.vctxt;
                    }
                } else {
                //The result is empty
                }
            }

            http:Response res = new;
            res.setPayload(<@untainted>vcText);
            res.setContentType("text/html; charset=utf-8");
            res.setHeader("Access-Control-Allow-Origin", "*");
            res.setHeader("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE");
            res.setHeader("Access-Control-Allow-Headers", "Authorization, Lang");

            var result = caller->respond(res);
            if (result is error) {
                log:printError("Error sending response", err = result);
            }

        }
    }

}
