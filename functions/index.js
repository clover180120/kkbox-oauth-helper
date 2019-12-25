const functions = require('firebase-functions');
const admin = require('firebase-admin');
const rp = require('request-promise');
const cors = require('cors')({origin: true});

admin.initializeApp();

exports.getToken = functions.https.onRequest(async (req, resp) => {
    const util = require('util');
    var db = admin.firestore().collection('kkbox_oauth');

    var path = (req.baseUrl == '') ? req._parsedUrl.pathname : req.baseUrl;
    var path_arr = path.split('/');
    
    var ret_url = '';
    var req_body = {
        'grant_type': 'authorization_code',
        'code': req.query.code,
        'client_id': null,
        'client_secret': null
    };
    var account_resp = {};
    var key_site_id = 'site_' + path_arr[(path_arr.length-2)];

    var getToken = await db.doc(key_site_id).get().then(async function (doc) {
        if (!doc.exists) {
            resp.status(404).end("{'state':404,'msg':'Not Found'}");
        } else {
            ret_url = doc.data().return_url;
            req_body.client_id = doc.data().client_id;
        }
    }).then(async function() {
        req_body.client_secret = await db.doc('client_' + req_body.client_id).get().then(async function(doc2) {
            return doc2.data().secret;
        });
    }).then(async function () {
        var opt = {
            'uri': 'https://account.kkbox.com/oauth2/token',
            'method': 'POST',
            'json': false,
            'headers': {
                'content-type': 'application/x-www-form-urlencoded'
            },
            'resolveWithFullResponse': true,
            'form': req_body
        }
        account_resp = await rp(opt);

        resp.redirect(ret_url + '?state=' + req.query.state + '&ret=' + encodeURI(account_resp.body));
    }).catch(err => {
        resp.status(500).end(JSON.stringify({
            'state': 500, 'msg': util.inspect(err)
        }));
    });
});

exports.addNewSite = functions.https.onRequest(async (req, resp) => {
    const util = require('util');
    const sha = require('crypto').createHash('sha256');

    var db = admin.firestore().collection('kkbox_oauth');
    var str = req.body.clientId + ':' + req.body.clientSecret;
    var sha256sum = '';
    var site_id = '';
    var key_site_id = '';
    var key_client_id = 'client_' + req.body.clientId;
    
    // check client_id / secret valid
    if(!req.body.clientId || !req.body.clientSecret || !req.body.returnUrl) {
        resp.status(400).end("{'state':400,'msg':'Bad Request'}");
    }

    var getClient = await db.doc(key_client_id).get().then(async function (doc) {
        if (!doc.exists || req.body.clientSecret == doc.data().secret) {
            sha256sum = sha.update(str, 'binary').digest('hex');
            site_id = sha256sum.substr(4, 6);
            key_site_id = 'site_' + site_id;

            return key_site_id;
        } else {
            resp.status(401).end("{'state':401,'msg':'Unauthorized'}");
        }
    }).then(async function() {
        var now = Math.floor((Date.now() / 1000));
        var client_info = {
            'secret': req.body.clientSecret,
            'ctime': now 
        };
        var site_info = {
            'client_id': req.body.clientId,
            'return_url': req.body.returnUrl,
            'atime': now 
        };
        var client_ret = db.doc(key_client_id).set(client_info);
        var site_ret = db.doc(key_site_id).set(site_info);
        
        resp.send({'state':200,'siteId':site_id,'retUrl':req.body.returnUrl,'msg':'add client/site successful'});
    }).catch(err => {
        resp.status(500).end(JSON.stringify({
            'state': 500, 'msg': util.inspect(err)
        }));
    });
});

