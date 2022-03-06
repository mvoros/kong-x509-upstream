const crypto = require("crypto");
const forge = require("node-forge");
const fs = require("fs");

let certCache = {};
let rootCert = {};
let newCertCache = {};

const loadCerts = function (service, config, logger) {
	logger.info(`Loading certificates used for signing x509 ${config.cert} ${config.private_key} service ${service}`);

	if (config.no_cert_cache) {
		logger.info("Caching of certificates is disabled");
	}

	const rootCAFile = fs.readFileSync(config.cert);
	const rootCA = forge.pki.certificateFromPem(rootCAFile);

	const rootKeyFile = fs.readFileSync(config.private_key);
	const privateKey = forge.pki.privateKeyFromPem(rootKeyFile);

	rootCert[service] = {
		cert: rootCA,
		privateKey: privateKey,
		validSecs: config.cert_validity_secs
	};

	//Prepare cert cache per service
	certCache[service] = {};
};

const generateNewCert = function (service, user, logger) {
	const cert = forge.pki.createCertificate();

	//Generate random serial number
	cert.serialNumber = "01" + crypto.randomBytes(19).toString("hex");
	logger.info(`New cert serial number ${cert.serialNumber} ${user}/${service}`);

	//Re-use public key of root cert
	cert.publicKey = rootCert[service].cert.publicKey;

	//Cert validity
	cert.validity.notBefore = new Date();
	cert.validity.notAfter = new Date(cert.validity.notBefore.getTime() + 1000 * rootCert[service].validSecs);

	const certAttributes = [
		{
			shortName: "CN",
			value: user
		}
	];
	cert.setSubject(certAttributes);

	cert.setExtensions([
		{
			name: "extKeyUsage",
			serverAuth: false,
			clientAuth: true,
			codeSigning: false,
			emailProtection: false,
			timeStamping: true
		}
	]);

	cert.setIssuer(rootCert[service].cert.subject.attributes);
	cert.sign(rootCert[service].privateKey);

	return cert;
};

const getCachedCert = function (service, user, logger) {
	//Check if we already have a valid cert
	const cert = certCache[service][user];

	if (cert) {
		//Return cert only if it's still valid

		const now = new Date();
		if (now < cert.validity.notAfter) {
			logger.info(`Serving cert ${cert.serialNumber} from cache service ${service}`);
			return cert;
		} else {
			loggger.info(`Removing obsolete cert ${cert.serialNumber} from cache service ${service}`);
			delete certCache[service][user];
			return null;
		}
	}

	return null;
};

const getCert = function (service, user, logger) {
	const cert = getCachedCert(service, user, logger);
	return cert ? cert : generateNewCert(service, user, logger);
};

const setCert = function (service, user, cert, logger) {
	if (!certCache[service][user]) {
		logger.info(`Caching certificate ${cert.serialNumber} service ${service}`);
		certCache[service][user] = cert;
		return;
	}

	//Replace old certificate if serial numbers do not match
	if (certCache[service][user].serialNumber !== cert.serialNumber) {
		logger.info(`Caching certificate ${cert.serialNumber} service ${service}`);
		certCache[service][user] = cert;
	}
};

class CertUpstreamPlugin {
	constructor(config) {
		this.config = config;
	}

	async access(kong) {
		const service = await kong.router.getService();
		kong.log.info(`Service ${service.name}`);

		if (!rootCert[service.name]) {
			loadCerts(service.name, this.config, kong.log);
		}

		//Determine identity that will be used for x509
		let user = "";
		if (this.config.fixed_identity) {
			user = this.config.fixed_identity;
		} else {
			const credential = await kong.client.getCredential();
			user = credential?.username;
		}

		if (user === "") {
			kong.log.err("Can't determine identity for x509 certificate");
			return;
		}

		//Generate x509 that will be sent to upstream system
		const clientCert = getCert(service.name, user, kong.log);

		//Set HTTP header
		await kong.service.request.setHeader(
			this.config.http_header_name,
			forge.util.encode64(forge.pki.certificateToPem(clientCert))
		);

		//Store values so we can cache cert later
		if (this.config.no_cert_cache) {
			return;
		}

		await kong.ctx.shared.set("newClientCert", clientCert.serialNumber);
		await kong.ctx.shared.set("service", service.name);
		await kong.ctx.shared.set("identity", user);
		newCertCache[clientCert.serialNumber] = clientCert;
	}

	async log(kong) {
		//Do not cache cert if backend responded with an error
		//Error may not be related to generated cert but play it safe
		//to avoid caching an incorrect cert
		const status = await kong.response.getStatus();
		if (status < 200 || status > 299) {
			return;
		}

		const newSerial = await kong.ctx.shared.get("newClientCert");
		if (!newSerial) {
			return;
		}

		const service = await kong.ctx.shared.get("service");
		const identity = await kong.ctx.shared.get("identity");

		if (newCertCache[newSerial]) {
			setCert(service, identity, newCertCache[newSerial], kong.log);
			delete newCertCache[newSerial];
		}
	}
}

module.exports = {
	Plugin: CertUpstreamPlugin,
	Schema: [
		{ private_key: { type: "string" } },
		{ cert: { type: "string" } },
		{ cert_validity_secs: { type: "number", default: 300 } },
		{ http_header_name: { type: "string", default: "ssl_client_cert" } },
		{ fixed_identity: { type: "string" } },
		{ no_cert_cache: { type: "boolean", default: false } }
	],
	Version: "0.1.0",
	Priority: 0
};
