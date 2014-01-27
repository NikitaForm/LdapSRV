var ldap = require('ldapjs');
var config = require('./libs/config');
var SUFFIX = 'o=users';
var db = config.get('users');
var server = ldap.createServer();

server.bind(SUFFIX, function(req, res, next) {
    var dn = req.dn.toString();
    if (!db[dn])
        return next(new ldap.NoSuchObjectError(dn));

    if (!db[dn].userpassword)
        return next(new ldap.NoSuchAttributeError('userPassword'));

    if (db[dn].userpassword !== req.credentials)
        return next(new ldap.InvalidCredentialsError());

    res.end();
    return next();
});

server.search(SUFFIX, function(req, res, next) {

    var dn = req.dn.toString();
    if (!db[dn]){
        return next(new ldap.NoSuchObjectError(dn));
    }
    var scopeCheck;
    switch (req.scope) {
        case 'base':
            if (req.filter.matches(db[dn])) {
                res.send({
                    dn: dn,
                    attributes: db[dn]
                });
            }
            res.end();
            return next();

        case 'one':
            scopeCheck = function(k) {
                if (req.dn.equals(k))
                    return true;
                var parent = ldap.parseDN(k).parent();
                return (parent ? parent.equals(req.dn) : false);
            };
            break;

        case 'sub':
            scopeCheck = function(k) {
                return (req.dn.equals(k) || req.dn.parentOf(k));
            };
            break;
    }

    Object.keys(db).forEach(function(key) {
        if (!scopeCheck(key))
            return;

        if (req.filter.matches(db[key])) {
            res.send({
                dn: key,
                attributes: db[key]
            });
        }
    });

    res.end();
    return next();
});

server.listen(process.env.PORT || 1389, 'sleepy-caverns-7803dfgdfg', function() {
    console.log('LDAP server up at: %s', server.url);
});
