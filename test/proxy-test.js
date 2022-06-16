
"use strict";

var assert = require("assert");
var ejs = require("ejs");
var fs = require("fs");
var supertest = require("supertest");

var config = require("../config");
var httpConstants = require("../http-constants");
var patterns = require("../main/patterns");

var SAFE_QUERY_STRING = "?username=tom&password=jones";
var SAFE_BODY = {
    username: "tom",
    password: "jones"
};
var MALICIOUS_BODY = {
    username: "tom",
    password: "jones' OR 5=5"
};

var proxyUrl = "http://localhost:" + config.proxyPort;

var template = fs.readFileSync(__dirname + "/../main/view/index.html", "utf8");


describe("xác minh yêu cầu an toàn", function() {

    it("Phương thức GET không tham số", function(done) {
        supertest(proxyUrl)
            .get("/default")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("safe GET with attributes", function(done) {
        supertest(proxyUrl)
            .get("/default/customers/7/users/129")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("Phương thức GET có tham số", function(done) {
        supertest(proxyUrl)
            .get("/default" + SAFE_QUERY_STRING)
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("Phương thức DELTE có tham số", function(done) {
        supertest(proxyUrl)
            .delete("/default" + SAFE_QUERY_STRING)
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("phương thức POST không có tham số", function(done) {
        supertest(proxyUrl)
            .post("/default")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("phương thức POST có tham số", function(done) {
        supertest(proxyUrl)
            .post("/default")
            .send(SAFE_BODY)
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("Phương thức PUT có tham số", function(done) {
        supertest(proxyUrl)
            .put("/default")
            .send(SAFE_BODY)
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

});

describe("Xác minh lỗi 400 || 500", function() {

    it("Phương thức GET không tìm thấy tài nguyên", function(done) {
        supertest(proxyUrl)
            .get("/someNonexistentEndpoint")
            .expect(httpConstants.responseCodes.HTTP_NOT_FOUND)
            .end(function(error) {
                if (error) {
                    throw error;
                }
                done();
            });
    });

    it("Lỗi server", function(done) {
        supertest(proxyUrl)
            .get("/server_error")
            .expect(httpConstants.responseCodes.HTTP_INTERNAL_SERVER_ERROR)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

});

describe("Kiểm tra lỗi SQL injection cho các phương thức", function() {

    it("Lỗi phương thức GET với dữ liệu truyền đi chứa câu lệnh luôn đúng", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom&password=jones' OR 1=1")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[0].description}));
                done();
            });
    });

    it("Lỗi phương thức GET với dữ liệu truyền đi chứa từ khóa SQL", function(done) {
        supertest(proxyUrl)
            .get("/default/customers/7/users/; DROP TABLES;")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[1].description}));
                done();
            });
    });

    it("Lỗi phương thức POST với dữ liệu truyền đi chứa câu lệnh luôn đúng", function(done) {
        supertest(proxyUrl)
            .post("/default")
            .set(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_FORM)
            .send(MALICIOUS_BODY)
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.body.message, patterns[0].description);
                done();
            });
    });

    it("Lỗi phương thức PUT với dữ liệu truyền đi chứa câu lệnh luôn đúng", function(done) {
        supertest(proxyUrl)
            .put("/default")
            .set(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_FORM)
            .send(MALICIOUS_BODY)
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.body.message, patterns[0].description);
                done();
            });
    });

    it("Lỗi phương thức DELETE với dữ liệu truyền đi chứa câu lệnh luôn đúng", function(done) {
        supertest(proxyUrl)
            .delete("/default?username=tom&password=jones' OR 1=1")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.body.message, patterns[0].description);
                done();
            });
    });
});

describe("Lỗi SQLi", function() {

    it("Phương thức GET với dữ liệu truyền đi chứa câu lệnh luôn đúng", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom&password=jones' OR 'test'='test'")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[0].description}));
                done();
            });
    });

    it("Phương thức GET với dữ liệu truyền đi chứa từ khóa SQL", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom&password=jones' OR 'test' LIKE 'test'")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[1].description}));
                done();
            });
    });

    it("Phương thức GET với dữ liệu truyền đi chứa từ khóa SQL", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom&password=jones' DROP TABLES;")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[1].description}));
                done();
            });
    });

});

describe("Lỗi chứa hàm SQL liên quan đến tên người dùng, tên database, tên server, ...", function() {
    it("Thông báo lỗi lộ tên người dùng cơ sở dữ liệu (MS SQL)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom' OR 1=convertint(int, USER)")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[3].description}));
                done();
            });
    });

    it("Thông báo lỗi lộ tên người dùng cơ sở dữ liệu (MS SQL)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom' OR CAST(CURRENT_USER() AS SIGNED INTEGER)")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[2].description}));
                done();
            });
    });

});

describe("Phát hiện Blind SQL Injection", function() {
    it("Phương thức GET với dữ liệu truyền đi chứa câu lệnh làm trễ thời gian phản hồi", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(LENGTH(CURRENT_USER)=1, SLEEP(5), false)")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[2].description}));
                done();
            });
    });

    it("Phương thức GET với dữ liệu truyền đi chứa câu lệnh làm trễ thời gian phản hồi", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(LEN(USER)=1) WAITFOR DELAY '00:00:05'")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[3].description}));
                done();
            });
    });

    it("Phương thức GET với dữ liệu truyền đi chứa câu lệnh làm trễ thời gian phản hồi", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(SUBSTRING(CURRENT_USER(),1,1)='a', SLEEP(5), false)")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[2].description}));
                done();
            });
    });

    it("Phương thức GET với dữ liệu truyền đi chứa câu lệnh làm trễ thời gian phản hồi", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(SUBSTRING(USER,1,1)='a') WAITFOR DELAY '00:00:05'")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[3].description}));
                done();
            });
    });

    it("Phương thức GET với dữ liệu truyền đi chứa câu lệnh làm trễ thời gian phản hồi", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(SUBSTRING(CURRENT_USER(),1,1)=X'97', SLEEP(5), false)")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[2].description}));
                done();
            });
    });

    it("Phương thức GET với dữ liệu truyền đi chứa câu lệnh làm trễ thời gian phản hồi", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(SUBSTRING(USER,1,1)=97) WAITFOR DELAY '00:00:05'")
            .expect(httpConstants.responseCodes.HTTP_SUCCESS_OK)
            .expect(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[3].description}));
                done();
            });
    });

});
