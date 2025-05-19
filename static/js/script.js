$(document).ready(function() {
    $('#uploadForm').on('submit', function(e) {
        e.preventDefault();
        $('#loading').removeClass('hidden');
        $('#uploadStatus').text('').removeClass('text-red-600 text-green-600');
        let formData = new FormData(this);
        
        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            headers: {
                'X-CSRF-Token': $('input[name="csrf_token"]').val()  // Include CSRF token in headers
            },
            success: function(response) {
                $('#loading').addClass('hidden');
                $('#uploadStatus').text('Upload successful! Redirecting...').addClass('text-green-600');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            },
            error: function(xhr) {
                $('#loading').addClass('hidden');
                $('#uploadStatus').text('Error uploading file: ' + (xhr.responseJSON?.message || 'Unknown error')).addClass('text-red-600');
            }
        });
    });
});