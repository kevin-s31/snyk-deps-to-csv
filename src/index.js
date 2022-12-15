#!/usr/bin/env node
"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var yargs = require("yargs");
var snyk_request_manager_1 = require("snyk-request-manager");
var debugLib = require("debug");
var fs = require("fs");
var process_1 = require("process");
var readline = require('readline');
var debug = debugLib('snyk:index');
var m = new Date();
var LOG_TIMESTAMP = m.getUTCFullYear() +
    '_' +
    ('0' + (m.getUTCMonth() + 1)).slice(-2) +
    '_' +
    ('0' + m.getUTCDate()).slice(-2) +
    '_' +
    ('0' + m.getUTCHours()).slice(-2) +
    '_' +
    ('0' + m.getUTCMinutes()).slice(-2) +
    '_' +
    ('0' + m.getUTCSeconds()).slice(-2) +
    '_' +
    ('0' + m.getUTCMilliseconds()).slice(-2) +
    '';
var LOG_FILE = "snyk-deps-to-csv.log";
var CSV_FILE = "snyk-deps_".concat(LOG_TIMESTAMP, ".csv");
var argv = yargs
    .usage("\nUsage: $0 [OPTIONS]\n                If no arguments are specified, values will be picked up from environment variables.\n\n                If pointing to a self-hosted or on-premise instance of Snyk,\n                SNYK_API is required to be set in your environment,\n                e.g. SNYK_API=https://my.snyk.domain/api. If omitted, then Snyk SaaS is used.")
    .options({
    'token': {
        describe: "your snyk token \n                       if not specified, then taken from SNYK_TOKEN",
        demandOption: true
    },
    'group-id': {
        describe: "the id of the group to process \n                       if not specified, then taken from SNYK_GROUP",
        demandOption: true
    },
    'dependency-list': {
        describe: "comma-delimited list of dependencies to filter results for \n                       if not specified, then all dependencies are retrieved",
        demandOption: false
    }
})
    .help().argv;
var token = argv['token'];
var groupId = argv['group-id'];
var dependencyList = argv['dependency-list'];
var requestManager = new snyk_request_manager_1.requestsManager({
    snykToken: String(argv['token']),
    userAgentPrefix: 'snyk-deps-to-csv',
    burstSize: 1,
    period: 425
});
function writeToCSV(message) {
    //console.log(message);
    fs.appendFileSync(CSV_FILE, "".concat(message, "\n"));
}
function printProgress(progress) {
    readline.cursorTo(process.stdout, 0);
    process.stdout.write("".concat(progress));
}
function processQueue(queue) {
    return __awaiter(this, void 0, void 0, function () {
        var numProcessed, numAdditionallyFetched, totalDepsCount;
        return __generator(this, function (_a) {
            numProcessed = 0;
            numAdditionallyFetched = 0;
            totalDepsCount = 0;
            console.log("processing ".concat(queue.length, " orgs for dependency data..."));
            try {
                queue.forEach(function (url) {
                    var _a, _b;
                    return __awaiter(this, void 0, void 0, function () {
                        var totalDeps, result, additionalPages, _c, _d, _i, totalDeps_1, dep, _e, _f, project, projectUrl;
                        return __generator(this, function (_g) {
                            switch (_g.label) {
                                case 0:
                                    totalDeps = [];
                                    return [4 /*yield*/, requestManager.request(url)];
                                case 1:
                                    result = _g.sent();
                                    if (!(result.data.total != "0")) return [3 /*break*/, 4];
                                    //console.log(`total deps found: ${result.data.total}`)
                                    totalDeps = result.data.results;
                                    additionalPages = Math.floor(Number(result.data.total) / 1000);
                                    numAdditionallyFetched += additionalPages;
                                    if (!(additionalPages > 0)) return [3 /*break*/, 3];
                                    _d = (_c = totalDeps).concat;
                                    return [4 /*yield*/, getMoreDepsPages(url.url, url.body, additionalPages)];
                                case 2:
                                    //splice additional data to base data
                                    totalDeps = _d.apply(_c, [_g.sent()]);
                                    _g.label = 3;
                                case 3:
                                    for (_i = 0, totalDeps_1 = totalDeps; _i < totalDeps_1.length; _i++) {
                                        dep = totalDeps_1[_i];
                                        //debug(`dep: ${JSON.stringify(dep)}`)
                                        for (_e = 0, _f = dep.projects; _e < _f.length; _e++) {
                                            project = _f[_e];
                                            projectUrl = "https://app.snyk.io/org/".concat(url.orgSlug, "/project/").concat(project.id);
                                            writeToCSV("".concat(url.orgSlug, ",").concat(url.orgId, ",").concat((_a = dep.id) === null || _a === void 0 ? void 0 : _a.replace(',', ';'), ",").concat(dep.name, ",").concat((_b = dep.version) === null || _b === void 0 ? void 0 : _b.replace(',', ';'), ",").concat(dep.latestVersion, ",").concat(dep.latestVersionPublishedDate, ",").concat(dep.firstPublishedDate, ",").concat(dep.isDeprecated, ",").concat(project.name, ",").concat(project.id, ",").concat(projectUrl));
                                        }
                                    }
                                    totalDepsCount += totalDeps.length;
                                    _g.label = 4;
                                case 4:
                                    printProgress(" - ".concat(++numProcessed, "/").concat(queue.length, " completed (additional paged requests: ").concat(numAdditionallyFetched, ", total deps: ").concat(totalDepsCount, ")"));
                                    return [2 /*return*/];
                            }
                        });
                    });
                });
            }
            catch (err) {
                console.log("error occurred: ".concat(err));
            }
            return [2 /*return*/];
        });
    });
}
function getMoreDepsPages(baseURL, filterBody, additionalPages) {
    return __awaiter(this, void 0, void 0, function () {
        var deps, queue, page, url, results, err_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    deps = [];
                    queue = [];
                    // build request list for concurrency
                    for (page = 2; page <= (additionalPages + 1); page++) {
                        url = "".concat(baseURL, "&page=").concat(page);
                        debug("queueing url: ".concat(url));
                        queue.push({
                            verb: 'POST',
                            url: "".concat(url),
                            body: filterBody
                        });
                    }
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, requestManager.requestBulk(queue)];
                case 2:
                    results = _a.sent();
                    //console.log(`found ${res.data.results.length} results for ${JSON.stringify(reqData)}`)
                    results.forEach(function (result) {
                        deps = deps.concat(result.data.results);
                        //console.log(result.data.results)
                    });
                    return [3 /*break*/, 4];
                case 3:
                    err_1 = _a.sent();
                    console.log("error occurred: ".concat(err_1));
                    return [3 /*break*/, 4];
                case 4: return [2 /*return*/, deps];
            }
        });
    });
}
function getSnykOrgs() {
    return __awaiter(this, void 0, void 0, function () {
        var orgs, response, err_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    orgs = [];
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, requestManager.request({
                            verb: 'GET',
                            url: "/orgs"
                        })];
                case 2:
                    response = _a.sent();
                    orgs = response.data.orgs;
                    orgs = orgs.filter(function (el) {
                        return el.group && el.group.id == groupId;
                    });
                    debug("orgs: ".concat(JSON.stringify(orgs)));
                    return [3 /*break*/, 4];
                case 3:
                    err_2 = _a.sent();
                    console.log(err_2);
                    return [3 /*break*/, 4];
                case 4: return [2 /*return*/, orgs];
            }
        });
    });
}
function app() {
    return __awaiter(this, void 0, void 0, function () {
        var filterBody, queue, orgs, _i, orgs_1, org;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    debug("token: ".concat(token));
                    debug("groupId: ".concat(groupId));
                    filterBody = {};
                    if (dependencyList) {
                        debug("dependencyList: ".concat(dependencyList));
                        try {
                            filterBody = { "filters": { "dependencies": String(dependencyList).split(',') } };
                        }
                        catch (err) {
                            console.log("error parsing dependency-list, exiting...");
                            (0, process_1.exit)(1);
                        }
                        console.log("filtering dependencies for ".concat(JSON.stringify(String(dependencyList).split(','), null, 2), "\n"));
                    }
                    writeToCSV("org-slug,org-id,dep-id,dep-name,dep-version,latestVersion,latestVersionPublishedDate,firstPublishedDate,isDeprecated,project-name,project-id,project-url");
                    queue = [];
                    return [4 /*yield*/, getSnykOrgs()];
                case 1:
                    orgs = _a.sent();
                    debug("orgs: ".concat(orgs));
                    for (_i = 0, orgs_1 = orgs; _i < orgs_1.length; _i++) {
                        org = orgs_1[_i];
                        debug("org.id: ".concat(org.id));
                        queue.push({
                            verb: 'POST',
                            url: "/org/".concat(org.id, "/dependencies?perPage=1000"),
                            body: filterBody,
                            orgId: org.id,
                            orgSlug: org.slug
                        });
                    }
                    return [4 /*yield*/, processQueue(queue)];
                case 2:
                    _a.sent();
                    console.log("writing results to ".concat(CSV_FILE, "\n"));
                    return [2 /*return*/];
            }
        });
    });
}
app();
