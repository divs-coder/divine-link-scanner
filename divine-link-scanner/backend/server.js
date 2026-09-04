require("dotenv").config();

const express = require("express");
const axios = require("axios");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 5000;

const ML_SERVICE_URL =
    process.env.ML_SERVICE_URL || "http://127.0.0.1:8000";

const VT_API_KEY = process.env.VT_API_KEY;

const VT_BASE_URL =
    "https://www.virustotal.com/api/v3";


// ========================================
// MIDDLEWARE
// ========================================

app.use(
    cors({
        origin: true,
        credentials: false
    })
);

app.use(express.json());


// ========================================
// BASIC HELPERS
// ========================================

function sleep(ms) {
    return new Promise(resolve => {
        setTimeout(resolve, ms);
    });
}


function makeUrlId(url) {
    return Buffer
        .from(url)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}


function formatDate(timestamp) {
    if (
        timestamp === null ||
        timestamp === undefined
    ) {
        return null;
    }

    const number = Number(timestamp);

    if (!Number.isFinite(number)) {
        return null;
    }

    const date = new Date(number * 1000);

    if (Number.isNaN(date.getTime())) {
        return null;
    }

    return date.toISOString();
}


function getVirusTotalHeaders() {
    return {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    };
}


// ========================================
// HEALTH CHECK
// ========================================

app.get("/", (req, res) => {
    res.json({
        success: true,
        service: "Divine Link Scanner",
        status: "online"
    });
});


// ========================================
// FRAUD CHECK
// ========================================

app.post("/api/fraud-check", async (req, res) => {
    try {
        const {
            amount,
            transactions_today,
            account_age_days,
            is_new_device,
            unusual_location
        } = req.body;

        if (
            amount === undefined ||
            transactions_today === undefined ||
            account_age_days === undefined
        ) {
            return res.status(400).json({
                success: false,
                error: "Missing transaction fields."
            });
        }

        const mlResponse = await axios.post(
            `${ML_SERVICE_URL}/predict`,
            {
                amount,
                transactions_today,
                account_age_days,
                is_new_device: Boolean(is_new_device),
                unusual_location: Boolean(unusual_location)
            },
            {
                timeout: 30000
            }
        );

        return res.json({
            success: true,
            fraud_detection: mlResponse.data
        });

    } catch (error) {
        console.error(
            "Fraud detection error:",
            error.response?.data || error.message
        );

        return res.status(500).json({
            success: false,
            error:
                error.response?.data?.detail ||
                error.response?.data?.error ||
                "Fraud detection service unavailable."
        });
    }
});


// ========================================
// URL SCAN
// ========================================

app.post("/api/url-scan", async (req, res) => {
    try {
        if (!VT_API_KEY) {
            return res.status(500).json({
                success: false,
                error:
                    "VirusTotal API key is missing. Add VT_API_KEY to your .env file."
            });
        }

        const { url } = req.body;

        if (!url || typeof url !== "string") {
            return res.status(400).json({
                success: false,
                error: "A URL is required."
            });
        }

        let parsedUrl;

        try {
            parsedUrl = new URL(url);
        } catch {
            return res.status(400).json({
                success: false,
                error: "Invalid URL."
            });
        }

        if (
            parsedUrl.protocol !== "http:" &&
            parsedUrl.protocol !== "https:"
        ) {
            return res.status(400).json({
                success: false,
                error:
                    "Only HTTP and HTTPS URLs are supported."
            });
        }


        // ========================================
        // SUBMIT TO VIRUSTOTAL
        // ========================================

        console.log(
            `Scanning URL: ${url}`
        );

        const formData =
            new URLSearchParams();

        formData.append(
            "url",
            url
        );

        const submitResponse =
            await axios.post(
                `${VT_BASE_URL}/urls`,
                formData.toString(),
                {
                    headers: {
                        ...getVirusTotalHeaders(),
                        "Content-Type":
                            "application/x-www-form-urlencoded"
                    },
                    timeout: 30000
                }
            );


        const analysisId =
            submitResponse.data?.data?.id;


        if (!analysisId) {
            return res.status(502).json({
                success: false,
                error:
                    "VirusTotal did not return an analysis ID."
            });
        }


        // ========================================
        // WAIT FOR REAL ANALYSIS
        // ========================================

        let analysisData = null;

        const maxChecks = 12;

        const delay = 2500;


        for (
            let attempt = 1;
            attempt <= maxChecks;
            attempt++
        ) {

            await sleep(delay);


            try {

                const analysisResponse =
                    await axios.get(
                        `${VT_BASE_URL}/analyses/${encodeURIComponent(analysisId)}`,
                        {
                            headers:
                                getVirusTotalHeaders(),

                            timeout: 30000
                        }
                    );


                analysisData =
                    analysisResponse.data?.data;


                const status =
                    analysisData?.attributes?.status;


                console.log(
                    `VirusTotal analysis ${attempt}/${maxChecks}: ${status}`
                );


                if (
                    status === "completed"
                ) {
                    break;
                }

            } catch (analysisError) {

                console.error(
                    "Analysis polling error:",
                    analysisError.response?.data ||
                    analysisError.message
                );
            }
        }


        if (!analysisData) {
            return res.status(502).json({
                success: false,
                error:
                    "VirusTotal analysis could not be retrieved."
            });
        }


        const analysisAttributes =
            analysisData.attributes || {};


        const analysisStats =
            analysisAttributes.stats || {};


        const analysisResults =
            analysisAttributes.results || {};


        // ========================================
        // GET REAL URL OBJECT
        // ========================================

        const urlId =
            makeUrlId(url);


        let urlAttributes = {};


        try {

            const urlResponse =
                await axios.get(
                    `${VT_BASE_URL}/urls/${encodeURIComponent(urlId)}`,
                    {
                        headers:
                            getVirusTotalHeaders(),

                        timeout: 30000
                    }
                );


            urlAttributes =
                urlResponse.data?.data?.attributes || {};

        } catch (urlError) {

            console.error(
                "URL object lookup failed:",
                urlError.response?.data ||
                urlError.message
            );
        }


        // ========================================
        // GET REAL DOMAIN DATA
        // ========================================

        const domain =
            parsedUrl.hostname;


        let domainAttributes = {};


        try {

            const domainResponse =
                await axios.get(
                    `${VT_BASE_URL}/domains/${encodeURIComponent(domain)}`,
                    {
                        headers:
                            getVirusTotalHeaders(),

                        timeout: 30000
                    }
                );


            domainAttributes =
                domainResponse.data?.data?.attributes || {};

        } catch (domainError) {

            console.error(
                "Domain lookup failed:",
                domainError.response?.data ||
                domainError.message
            );
        }


        // ========================================
        // REAL ENGINE RESULTS
        // ========================================

        const engines =
            Object.entries(
                analysisResults
            ).map(
                ([engineName, result]) => ({
                    engine: engineName,

                    category:
                        result?.category ??
                        null,

                    result:
                        result?.result ??
                        null,

                    method:
                        result?.method ??
                        null,

                    engine_name:
                        result?.engine_name ??
                        engineName,

                    engine_version:
                        result?.engine_version ??
                        null,

                    engine_update:
                        result?.engine_update ??
                        null
                })
            );


        // Sort engines so detections appear first
        engines.sort((a, b) => {

            const priority = {
                malicious: 0,
                suspicious: 1,
                phishing: 2,
                malware: 3,
                harmless: 4,
                undetected: 5,
                timeout: 6,
                failure: 7
            };

            const aPriority =
                priority[a.category] ??
                99;

            const bPriority =
                priority[b.category] ??
                99;

            return aPriority - bPriority;
        });


        // ========================================
        // URL INFORMATION
        // ========================================

        const scan = {

            // Original URL
            url: url,

            // Domain actually extracted from URL
            domain: domain,

            // Real VirusTotal metadata
            title:
                urlAttributes.title ??
                null,

            reputation:
                urlAttributes.reputation ??
                domainAttributes.reputation ??
                null,

            categories:
                urlAttributes.categories ||
                domainAttributes.categories ||
                {},

            first_submission_date:
                formatDate(
                    urlAttributes.first_submission_date
                ),

            last_submission_date:
                formatDate(
                    urlAttributes.last_submission_date
                ),

            last_analysis_date:
                formatDate(
                    urlAttributes.last_analysis_date
                ),

            domain_creation_date:
                formatDate(
                    domainAttributes.creation_date
                ),

            last_update_date:
                formatDate(
                    domainAttributes.last_update_date
                ),

            whois_date:
                formatDate(
                    domainAttributes.whois_date
                ),

            registrar:
                domainAttributes.registrar ??
                null,

            whois:
                domainAttributes.whois ??
                null,

            final_url:
                urlAttributes.last_final_url ??
                null,

            http_response_code:
                urlAttributes.last_http_response_code ??
                null,

            http_response_content_length:
                urlAttributes.last_http_response_content_length ??
                null,

            has_content:
                urlAttributes.has_content ??
                null,

            html_detected:
                Object.keys(
                    urlAttributes.html_meta || {}
                ).length > 0,

            html_meta:
                urlAttributes.html_meta ||
                {},

            // ====================================
            // REAL VIRUSTOTAL STATS
            // ====================================

            detections: {

                malicious:
                    Number(
                        analysisStats.malicious || 0
                    ),

                suspicious:
                    Number(
                        analysisStats.suspicious || 0
                    ),

                harmless:
                    Number(
                        analysisStats.harmless || 0
                    ),

                undetected:
                    Number(
                        analysisStats.undetected || 0
                    ),

                timeout:
                    Number(
                        analysisStats.timeout || 0
                    ),

                failure:
                    Number(
                        analysisStats.failure || 0
                    ),

                total_engines:
                    engines.length
            },

            // ====================================
            // RAW ENGINE RESULTS
            // ====================================

            engines: engines,

            // ====================================
            // ANALYSIS INFORMATION
            // ====================================

            analysis_id:
                analysisId,

            analysis_status:
                analysisAttributes.status ??
                null,

            analysis_date:
                formatDate(
                    analysisAttributes.date
                )
        };


        return res.json({
            success: true,
            scan
        });


    } catch (error) {

        console.error(
            "URL scan error:",
            error.response?.data ||
            error.message
        );


        let message =
            "Unable to complete URL scan.";


        if (
            error.response?.status === 401
        ) {

            message =
                "VirusTotal API key is invalid.";

        } else if (
            error.response?.status === 429
        ) {

            message =
                "VirusTotal rate limit reached. Please wait and try again.";

        } else if (
            error.response?.data?.error?.message
        ) {

            message =
                error.response.data.error.message;
        }


        return res.status(
            error.response?.status || 500
        ).json({
            success: false,
            error: message
        });
    }
});


// ========================================
// SERVER
// ========================================

app.listen(
    PORT,
    "127.0.0.1",
    () => {

        console.log("");
        console.log(
            "========================================"
        );

        console.log(
            "DIVINE LINK SCANNER"
        );

        console.log(
            "========================================"
        );

        console.log(
            `Server: http://127.0.0.1:${PORT}`
        );

        console.log(
            `ML Service: ${ML_SERVICE_URL}`
        );

        console.log(
            `VirusTotal: ${
                VT_API_KEY
                    ? "API KEY LOADED"
                    : "API KEY MISSING"
            }`
        );

        console.log(
            "========================================"
        );

    }
);