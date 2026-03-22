// Convert data-timestamp attributes to local timezone strings
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.local-time').forEach(function(el) {
        var ts = parseFloat(el.dataset.timestamp);
        if (!isNaN(ts)) {
            var d = new Date(ts * 1000);
            var year = d.getFullYear();
            var month = String(d.getMonth() + 1).padStart(2, '0');
            var day = String(d.getDate()).padStart(2, '0');
            var hours = String(d.getHours()).padStart(2, '0');
            var mins = String(d.getMinutes()).padStart(2, '0');
            var secs = String(d.getSeconds()).padStart(2, '0');
            var tz = d.toLocaleTimeString(
                'en-US', {timeZoneName: 'short'}).split(' ').pop();
            el.textContent = year + '-' + month + '-' + day + ' ' +
                hours + ':' + mins + ':' + secs + ' ' + tz;
        }
    });
});
