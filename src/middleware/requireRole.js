const requireAuth = require('./requireAuth');

/**
 * Returns middleware that allows only the specified roles.
 * Usage: requireRole('admin', 'fin-role')
 */
module.exports = function requireRole(...roles) {
  return function (req, res, next) {
    requireAuth(req, res, () => {
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ error: 'Access denied' });
      }
      next();
    });
  };
};
