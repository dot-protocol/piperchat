// pm2 ecosystem config for piperchat
// usage: pm2 start deploy/ecosystem.config.js
//        pm2 save
//        pm2 startup   (generate startup script)

module.exports = {
  apps: [
    {
      name:               'piperchat',
      script:             'server.js',
      cwd:                '/opt/piperchat',   // adjust to your deploy path
      exec_mode:          'fork',             // single process — sqlite is not multi-process safe
      instances:          1,
      max_memory_restart: '512M',
      restart_delay:      2000,
      autorestart:        true,
      watch:              false,
      log_file:           './logs/combined.log',
      out_file:           './logs/out.log',
      error_file:         './logs/err.log',
      merge_logs:         true,
      time:               true,              // prepend timestamps to log lines
      env: {
        NODE_ENV: 'production',
        PORT:     4101,
        DATA_DIR: '/opt/piperchat/data',
        // DB_PATH, ALLOWED_ORIGINS, POSTHOG_API_KEY — set in /etc/piperchat.env
        // and load with: env_file: '/etc/piperchat.env'
      },
    },
  ],
};
