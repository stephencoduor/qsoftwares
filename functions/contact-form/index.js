// Google Cloud Run functions entry point.
const functions = require('@google-cloud/functions-framework');
const { contactForm } = require('./core');

functions.http('contactForm', contactForm);
module.exports = { contactForm };
