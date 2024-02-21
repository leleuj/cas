const puppeteer = require("puppeteer");
const cas = require("../../cas.js");

(async () => {
    const browser = await puppeteer.launch(cas.browserOptions());
    const page = await cas.newPage(browser);
    await cas.goto(page, "https://127.0.0.1:8443/cas/login?authn_method=mfa-inwebo");
    await cas.loginWith(page, "testcasva", "password");
    await cas.waitForElement(page, "#vaContainer");
    await cas.screenshot(page);
    await cas.assertVisibility(page, "#vaContainer");
    await browser.close();
})();
