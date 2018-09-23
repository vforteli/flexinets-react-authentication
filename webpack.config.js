var path = require('path');

module.exports = {
    mode: 'production',
    entry: ['regenerator-runtime/runtime', './index.js'],
    output: {
        path: path.resolve('lib'),
        filename: 'flexinets-react-authentication.js',
        libraryTarget: 'commonjs2'
    },
    module: {
        rules: [
            {
                test: /\.jsx?$/,
                exclude: /(node_modules)/,
                use: 'babel-loader'
            }
        ]
    },
    externals: {
        'axios': 'axios',
        'jwt-decode': 'jwt-decode',
        'qs': 'qs'
    }
};