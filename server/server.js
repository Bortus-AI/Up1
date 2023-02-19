var crypto = require('crypto');
var fs = require('fs');
var path = require('path');

var Busboy = require('busboy');
var express = require('express');
var http = require('http');
var https = require('https');
var request = require('request');
var tmp = require('tmp');


// Different headers can be pushed depending on data format
// to allow for changes with backwards compatibility
var UP1_HEADERS = {
    v1: Buffer.from("UP1\0", 'binary')
}

var makeident = function(){
    var text = "";
	    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	    for( var i = 0; i < 22; i++ )
	        text += possible.charAt(Math.floor(Math.random() * possible.length));

	    return text;
}

var Base64={_keyStr:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function(e){var t="";var n,r,i,s,o,u,a;var f=0;e=Base64._utf8_encode(e);while(f<e.length){n=e.charCodeAt(f++);r=e.charCodeAt(f++);i=e.charCodeAt(f++);s=n>>2;o=(n&3)<<4|r>>4;u=(r&15)<<2|i>>6;a=i&63;if(isNaN(r)){u=a=64}else if(isNaN(i)){a=64}t=t+this._keyStr.charAt(s)+this._keyStr.charAt(o)+this._keyStr.charAt(u)+this._keyStr.charAt(a)}return t},decode:function(e){var t="";var n,r,i;var s,o,u,a;var f=0;e=e.replace(/[^A-Za-z0-9\+\/\=]/g,"");while(f<e.length){s=this._keyStr.indexOf(e.charAt(f++));o=this._keyStr.indexOf(e.charAt(f++));u=this._keyStr.indexOf(e.charAt(f++));a=this._keyStr.indexOf(e.charAt(f++));n=s<<2|o>>4;r=(o&15)<<4|u>>2;i=(u&3)<<6|a;t=t+String.fromCharCode(n);if(u!=64){t=t+String.fromCharCode(r)}if(a!=64){t=t+String.fromCharCode(i)}}t=Base64._utf8_decode(t);return t},_utf8_encode:function(e){e=e.replace(/\r\n/g,"\n");var t="";for(var n=0;n<e.length;n++){var r=e.charCodeAt(n);if(r<128){t+=String.fromCharCode(r)}else if(r>127&&r<2048){t+=String.fromCharCode(r>>6|192);t+=String.fromCharCode(r&63|128)}else{t+=String.fromCharCode(r>>12|224);t+=String.fromCharCode(r>>6&63|128);t+=String.fromCharCode(r&63|128)}}return t},_utf8_decode:function(e){var t="";var n=0;var r=c1=c2=0;while(n<e.length){r=e.charCodeAt(n);if(r<128){t+=String.fromCharCode(r);n++}else if(r>191&&r<224){c2=e.charCodeAt(n+1);t+=String.fromCharCode((r&31)<<6|c2&63);n+=2}else{c2=e.charCodeAt(n+1);c3=e.charCodeAt(n+2);t+=String.fromCharCode((r&15)<<12|(c2&63)<<6|c3&63);n+=3}}return t}}

function handle_upload(req, res) {
    var config = req.app.locals.config
    var busboy = new Busboy({
        headers: req.headers,
        limits: {
            fileSize: config.maximum_file_size,
            files: 1,
            parts: 3
        }
    });

    res.setHeader('Access-Control-Allow-Origin', '*');

    var code = 500
    var fields = {
        ident: makeident(),
    };
    var tmpfname = null;

    res.status(code);

    busboy.on('field', function(fieldname, value) {
        if (fieldname === 'ident') {
            return;
        }

        fields[fieldname] = value;

        if (fieldname === 'file') {
            try {
                var decoded = Base64.decode(value);

                var extension = undefined;
                var lowerCase = decoded.toLowerCase();

                if (lowerCase.indexOf("png") !== -1) {
                    extension = "png";
                }

                if (lowerCase.indexOf("jpg") !== -1 || lowerCase.indexOf("jpeg") !== -1) {
                    extension = "jpg";
                }

                if (lowerCase.indexOf("gif") !== -1) {
                    extension = "gif";
                }

                if (lowerCase.indexOf("jfif") !== -1) {
                    extension = "jfif";
                }

                if (!extension) {
                    throw new Error('bad extension');
                }

                fields.ident = fields.ident + '.' + extension;

                var ftmp = tmp.fileSync({ postfix: '.tmp', dir: req.app.locals.config.path.i2, keep: true });
                tmpfname = ftmp.name;

                var fstream = fs.createWriteStream('', {
                    fd: ftmp.fd,
                    defaultEncoding: 'binary',
                });

                var bf = Buffer.from(value, 'base64');

                fstream.write(bf);
            } catch (err) {
                if (res.json) {
                    res.json({ code: code, error: err });
                }

                if (req.unpipe) {
                    req.unpipe(busboy);
                }

                if (res.close) {
                    res.close();
                }
            }
        }
    });

    busboy.on('finish', function() {
        try {
            if (!tmpfname) {

                res.json({
                    code : code,
                    error : "Internal Server Error"
                });

            } else if (fields.api_key !== config['api_key']) {

                code = 408

                res.json({
                    code : code,
                    error : "API key doesn\'t match"
                });

            } else if (!fields.ident) {

                res.json({
                    code : code,
                    error : "Ident not provided"
                });

            } else if (ident_exists(fields.ident)) {
                res.json({
                    code : code,
                    error : "Ident is already taken"
                });

            } else {
                var delhmac = crypto.createHmac('sha256', config.delete_key)
                                    .update(fields.ident)
                                    .digest('hex');
                fs.rename(tmpfname, ident_path(fields.ident), function() {
                    code = 200
                    res.status(200)
                    res.json({
                        data : {
                            ident : fields.ident,
                            delkey: delhmac,

                        },
                        success : true
                    });
                });
            }
        } catch (err) {
            res.json({
                code : code,
                error : err
            });
        }
    });

    return req.pipe(busboy);
};


function handle_delete(req, res) {
    var config = req.app.locals.config
    if (!req.query.ident) {
        res.send('{"error": "Ident not provided", "code": 11}');
        return;
    }
    if (!req.query.delkey) {
        res.send('{"error": "Delete key not provided", "code": 12}');
        return;
    }
    var delhmac = crypto.createHmac('sha256', config.delete_key)
                        .update(req.query.ident)
                        .digest('hex');
    if (req.query.ident.length !== 22) {
        res.send('{"error": "Ident length is incorrect", "code": 3}');
    } else if (delhmac !== req.query.delkey) {
        res.send('{"error": "Incorrect delete key", "code": 10}');
    } else if (!ident_exists(req.query.ident)) {
        res.send('{"error": "Ident does not exist", "code": 9}');
    } else {
        fs.unlink(ident_path(req.query.ident), function() {
            cf_invalidate(req.query.ident, config);
            res.redirect('/');
        });
    }
};

function ident_path(ident) {
    return '../i/' + path.basename(ident);
}

function ident_exists(ident) {
    try {
        fs.lstatSync(ident_path(ident));
        return true;
    } catch (err) {
        return false;
    }
}

function cf_do_invalidate(ident, mode, cfconfig) {
    var inv_url = mode + '://' + cfconfig.url + '/i/' + ident;

    request.post({
        url: 'https://www.cloudflare.com/api_json.html',
        form: {
            a: 'zone_file_purge',
            tkn: cfconfig.token,
            email: cfconfig.email,
            z: cfconfig.domain,
            url: inv_url
        }
    }, function(err, response, body) {
        if (err) {
            console.error("Cache invalidate failed for", ident);
            console.error("Body:", body);
            return;
        }
        try {
            var result = JSON.parse(body)
            if (result.result === 'error') {
                console.error("Cache invalidate failed for", ident);
                console.error("Message:", msg);
            }
        } catch(err) {}
    });
}

function cf_invalidate(ident, config) {
    var cfconfig = config['cloudflare-cache-invalidate']
    if (!cfconfig.enabled) {
      return;
    }
    if (config.http.enabled)
        cf_do_invalidate(ident, 'http', cfconfig);
    if (config.https.enabled)
        cf_do_invalidate(ident, 'https', cfconfig);
}

function create_app(config) {
  var app = express();
  app.locals.config = config
  app.use('', express.static(config.path.client));

  app.use('/i', express.static(config.path.i, {
    setHeaders : function(res){
        res.setHeader('Access-Control-Allow-Origin', '*');
    }
  }));

  app.use('/i2', express.static(config.path.i2, {
    setHeaders : function(res){
        res.setHeader('Access-Control-Allow-Origin', '*');
    }
  }));

  app.post('/up', handle_upload);
  app.get('/del', handle_delete);
  return app
}

/* Convert an IP:port string to a split IP and port */
function get_addr_port(s) {
    var spl = s.split(":");
    if (spl.length === 1)
        return { host: spl[0], port: 80 };
    else if (spl[0] === '')
        return { port: parseInt(spl[1]) };
    else
        return { host: spl[0], port: parseInt(spl[1]) };
}

function serv(server, serverconfig, callback) {
  var ap = get_addr_port(serverconfig.listen);
  return server.listen(ap.port, ap.host, callback);
}

function init_defaults(config) {
  config.path = config.path ? config.path : {};
  config.path.i = config.path.i ? config.path.i : "../i";
  config.path.i2 = config.path.i2 ? config.path.i2 : "../i2";
  config.path.client = config.path.client ? config.path.client : "../client";
}

function init(config) {
  init_defaults(config)

  var app = create_app(config);

  if (config.http.enabled) {
    serv(http.createServer(app), config.http, function() {
      console.info('Started server at http://%s:%s', this.address().address, this.address().port);
    });
  }

  if (config.https.enabled) {
      var sec_creds = {
          key: fs.readFileSync(config.https.key),
          cert: fs.readFileSync(config.https.cert),
          passphrase: config.https.passphrase
      };

      serv(https.createServer(sec_creds, app), config.https, function() {
        console.info('Started server at https://%s:%s', this.address().address, this.address().port);
      });
  }
}

function main(configpath) {
  init(JSON.parse(fs.readFileSync(configpath)));
}

main('./server.conf')
