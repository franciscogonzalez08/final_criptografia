const express = require('express');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const app = express();

let storage = multer.diskStorage({
    destination: function (req, file, callback) {
        callback(null, './uploads');
    }, filename: function (req, file, callback) {
        callback(null, 'file.txt');
    }
});

let upload = multer({ storage: storage }).single('txtFile');


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => { console.log(`Server running on port ${PORT}`) });

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.status(200).sendFile(__dirname + '/public/index.html');
});

app.post('/uploadFile', function (req, res) {
    upload(req, res, function (err) {
        if (err) {
            console.log(`Error while uploading file, error info: ${err}.`);
            res.status(400).send(`Error while uploading file, error info: ${err}.`);
        }
        console.log('File uploaded.');

        const data = fs.readFileSync('uploads/file.txt', 'utf-8');
        if (data == null) {
            console.log('Error while reading file');
            res.status(400).send('Error while reading file');
        }

        // Generate keys
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048, //2048 bits
            publicKeyEncoding: {
                type: 'pkcs1',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs1',
                format: 'pem'
            }

        });

        // Encrypt file
        const encryptedData = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            Buffer.from(data)
        );

        // Decrypt data
        const decryptedData = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, encryptedData
        );

        // Sign document
        const signer = crypto.createSign('sha256');
        signer.write(data);
        signer.end();

        const signature = signer.sign(privateKey, 'base64');

        // Verify signature
        const verifier = crypto.createVerify('sha256');
        verifier.write(data);
        verifier.end();

        // Verify file signature
        const result = verifier.verify(publicKey, signature, 'base64');

        console.log('Digital Signature Verification : ' + result);

        let displayHTML = fs.readFileSync(__dirname + '/public/display.html', 'utf8');
        if (displayHTML == null) res.status(400).send('Error while loading encrypted data.');

        displayHTML = displayHTML.replace('encryptedData', `${encryptedData.toString('base64')}`);
        displayHTML = displayHTML.replace('decryptedData', decryptedData.toString());
        displayHTML = displayHTML.replace('signature', signature);


        res.status(200).send(displayHTML);
    });

});