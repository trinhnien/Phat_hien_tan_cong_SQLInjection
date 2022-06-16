
'use strict';

var patterns = [
    {
        // Lỗi điều kiện
        "regex": /\s(.+)=\1+/,
        "description": "Equality expression. (ex. 1=1)"
    },
    {
        // Lỗi chứa từ khóa trong SQL
        "regex": /\s(SELECT|DROP|UPDATE|CREATE|INSERT|ALTER|UNION|MERGE|LIKE)/i,
        "description": "SQL query keyword. (ex. DROP)"
    },
    {   // Lỗi chứa hàm SQL liên quan đến tên người dùng, tên database, tên server, ...
        "regex": /(CURRENT_USER|CURRENT_USER\(\)|USER\(\))/i,
        "description": "SQL function. (ex. CURRENT_USER())"
    },
    {
        "regex": /(USER)/,
        "description": "MS SQL function. (ex. USER)"
    },
    {
        // Lỗi các ký tự đặc biệt
        "regex": /'(''|[^'])*'/,
        "description": "SQL Statements"
    },
];

module.exports = patterns;