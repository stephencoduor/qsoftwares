/*---------------------------------------------
Template name:  BNSCloud
Version:        1.5
Author:         ThemeLooks
Author url:     http://themelooks.com

NOTE:
------
Please DO NOT EDIT THIS JS, you may need to use "custom.js" file for writing your custom js.
We may release future updates so it will overwrite this file. it's better and safer to use "custom.js".

[Table of Content]

01: Prevent empty links to scroll
02: Sticky header
03: Sticky Header Animation
04: Parsley form validation
05: Smooth scroll for scroll button
06: Smooth scroll for comment reply
07: Blog Hover Animation
08: Team member slider
09: Video popup
10: Back to top button
11: Counter
12: Google map
13: Changing svg color
14: Preloader
15: Content animation
16: Background Image
17: Mega Menu
18: Matrix Effect
19: Ajax Contact Form 

----------------------------------------------*/


(function($) {
    "use strict";
    $(function(){

        /* 01: Prevent empty links to scroll
        ==============================================*/

        $('.header-menu a[href="#"]').on('click', function(event) {
            event.preventDefault();
        });

        
        /* 02: Sticky header
        ==============================================*/

        var mainHeader = $('.main-header');

        if(mainHeader.length) {
            var sticky = new Waypoint.Sticky({
                element: mainHeader[0],
                stuckClass: 'sticking',
                offset: -1
            });
        };

        /* 03: Sticky Header Animation
        ==============================================*/
        $(window).on("scroll", function () {
            if ($(".main-header").hasClass("sticking")) {
                $(".main-header").addClass("fadeInDown animated");
            } else {
                $(".main-header").removeClass("fadeInDown animated");
            }
        });

        /* 04: Parsley form validation
        ==============================================*/

        $('form').parsley();


        /* 05: Smooth scroll for scroll button
        ==============================================*/
        
        var $mainBanner = $('.main-banner');
        
        $mainBanner.on('click', '.goDown', function(){
            var $target = $mainBanner.next();
            
            if ( $target.length ) {
                $('html, body').animate({
                    scrollTop: $target.offset().top - 50
                }, 500);
            }
        });


        /* 06: Smooth scroll for comment reply
        ==============================================*/
        
        var $commentContent = $('.comment-content > a');
        
        $commentContent.on('click', function(){
            var $target = $('.comment-form');
            
            if ( $target.length ) {
                $('html, body').animate({
                    scrollTop: $target.offset().top - 120
                }, 500);

                $target.find('textarea').focus();
            }
        });

        /* 07: Blog Hover
        ==============================================*/
        $(".single-post.post-style--2").on("mouseover", function(){
            $(this).find(".post-hover a").addClass("animated fadeInUp");
        });
        $(".single-post.post-style--2").on("mouseleave", function(){
            $(".post-hover a").removeClass("animated fadeInUp");
        });
        
        /* 08: Review slider
        ==============================================*/
        
        var swiperTeam = new Swiper('.review-slider', {
            slidesPerView: 3,
            spaceBetween: 30,
            autoplay: {
                delay: 5000,
                disableOnInteraction: true,
            },
            pagination: {
                el: '.review-pagination',
                clickable: true,
            },
            breakpoints: {
                // when window width is <= 575px
                575: {
                    slidesPerView: 1
                },
                // when window width is <=991px
                991: {
                    slidesPerView: 2
                }
            }
        });

        var swiperTeam = new Swiper('.review-slider--2', {
            slidesPerView: 1,
            loop: true,
            spaceBetween: 10,
            autoplay: {
                delay: 5000,
                disableOnInteraction: true,
            },
            navigation: {
                prevEl: '.prev-review',
                nextEl: '.next-review',
            }
        });

        var swiperTeam = new Swiper('.review-slider--3', {
            slidesPerView: 1,
            loop: true,
            autoplay: {
                delay: 5000,
                disableOnInteraction: true,
            },
            navigation: {
                prevEl: '.prev-review',
                nextEl: '.next-review',
            }
        });

        
        /* 09: Video popup
        ==============================================*/

        var $youtubePopup = $('.youtube-popup');

        if($youtubePopup.length) {

            $youtubePopup.magnificPopup({
                type:'iframe'
            });
        }

        
        /* 10: Back to top button
        ==============================================*/

        var $backToTopBtn = $('.back-to-top');

        if ($backToTopBtn.length) {
            var scrollTrigger = 400, // px
            backToTop = function () {
                var scrollTop = $(window).scrollTop();
                if (scrollTop > scrollTrigger) {
                    $backToTopBtn.addClass('show');
                } else {
                    $backToTopBtn.removeClass('show');
                }
            };

            backToTop();

            $(window).on('scroll', function () {
                backToTop();
            });

            $backToTopBtn.on('click', function (e) {
                e.preventDefault();
                $('html,body').animate({
                    scrollTop: 0
                }, 700);
            });
        }
        // Back to top button 2
        var amountScrolled = 650;
        var backBtn = $("a.back-top--2, a.back-top--3");
        $(window).on("scroll", function () {
            if ($(window).scrollTop() > amountScrolled) {
                backBtn.addClass("back-top-visible");
            } else {
                backBtn.removeClass("back-top-visible");
            }
        });
        backBtn.on("click", function () {
            $("html, body").animate({
                scrollTop: 0
            }, 700);
            return false;
        });


        /* 11: Counter
        ==============================================*/

        var happyCounter = $('.happy-counter li');

        if (happyCounter.length) {
            
            var a = 0;
            $(window).scroll(function() {

                var oTop = happyCounter.offset().top - window.innerHeight;
                if (a == 0 && $(window).scrollTop() > oTop) {

                    var $dataCount = $('[data-count]');

                    $dataCount.each(function() {
                        var $this = $(this),
                            countTo = $this.attr('data-count');
                        $({
                            countNum: $this.text()
                        }).animate({
                            countNum: countTo
                        },

                        {
                            duration: 2000,
                            easing: 'swing',
                            step: function() {
                                $this.text(Math.floor(this.countNum));
                            },
                            complete: function() {
                                $this.text(this.countNum);
                                //alert('finished');
                            }
                        });
                    });
                    a = 1;
                }
            }).scroll();
        }

        
        /* 12: Google map
        ==============================================*/

        var $map = $('[data-trigger="map"]'),
            $mapOps;

        if ( $map.length ) {
            // Map Options
            $mapOps = $map.data('map-options');

            // Map Initialization
            window.initMap = function () {
                $map.css('min-height', '410px');

                $map.each(function () {
                    var $t = $(this), map, lat, lng, zoom;

                    $mapOps = $t.data('map-options');
                    lat = parseFloat($mapOps.latitude, 10);
                    lng = parseFloat($mapOps.longitude, 10);
                    zoom = parseFloat($mapOps.zoom, 10);

                    map = new google.maps.Map($t[0], {
                        center: {lat: lat, lng: lng},
                        zoom: zoom,
                        scrollwheel: false,
                        disableDefaultUI: true,
                        zoomControl: true,
                        styles: [
                            {
                                "featureType": "water",
                                "elementType": "geometry",
                                "stylers": [{"color": "#e9e9e9"}, {"lightness": 17}]
                            },
                            {
                                "featureType": "landscape",
                                "elementType": "geometry",
                                "stylers": [{"color": "#f5f5f5"}, {"lightness": 20}]
                            },
                            {
                                "featureType": "road.highway",
                                "elementType": "geometry.fill",
                                "stylers": [{"color": "#ffffff"}, {"lightness": 17}]
                            },
                            {
                                "featureType": "road.highway",
                                "elementType": "geometry.stroke",
                                "stylers": [{"color": "#ffffff"}, {"lightness": 29}, {"weight": 0.2}]
                            },
                            {
                                "featureType": "road.arterial",
                                "elementType": "geometry",
                                "stylers": [{"color": "#ffffff"}, {"lightness": 18}]
                            },
                            {
                                "featureType": "road.local",
                                "elementType": "geometry",
                                "stylers": [{"color": "#ffffff"}, {"lightness": 16}]
                            },
                            {
                                "featureType": "poi",
                                "elementType": "geometry",
                                "stylers": [{"color": "#f5f5f5"}, {"lightness": 21}]
                            },
                            {
                                "featureType": "poi.park",
                                "elementType": "geometry",
                                "stylers": [{"color": "#dedede"}, {"lightness": 21}]
                            },
                            {
                                "elementType": "labels.text.stroke",
                                "stylers": [{"visibility": "on"}, {"color": "#ffffff"}, {"lightness": 16}]
                            },
                            {
                                "elementType": "labels.text.fill",
                                "stylers": [{"saturation": 36}, {"color": "#333333"}, {"lightness": 40}]
                            },
                            {
                                "elementType": "labels.icon",
                                "stylers": [{"visibility": "off"}]
                            },
                            {
                                "featureType": "transit",
                                "elementType": "geometry",
                                "stylers": [{"color": "#f2f2f2"}, {"lightness": 19}]
                            },
                            {
                                "featureType": "administrative",
                                "elementType": "geometry.fill",
                                "stylers": [{"color": "#fefefe"}, {"lightness": 20}]
                            },
                            {
                                "featureType": "administrative",
                                "elementType": "geometry.stroke",
                                "stylers": [{"color": "#fefefe"}, {"lightness": 17}, {"weight": 1.2}]
                            }
                        ]
                    });

                    map = new google.maps.Marker({
                        position: {lat: lat, lng: lng},
                        map: map,
                        animation: google.maps.Animation.DROP,
                        draggable: true,
                        icon: 'img/marker.png'
                    });
                });
            };

            // Map Script
            var googleAPI = document.createElement('script');

            googleAPI.type = 'text/javascript';
            googleAPI.src = 'https://maps.googleapis.com/maps/api/js?key='+ $mapOps.api_key +'&callback=initMap';

            $('body').append( googleAPI );
        }

        /* 13: Changing svg color
        ==============================================*/

        jQuery('img.svg').each(function(){
            var $img = jQuery(this);
            var imgID = $img.attr('id');
            var imgClass = $img.attr('class');
            var imgURL = $img.attr('src');
        
            jQuery.get(imgURL, function(data) {
                // Get the SVG tag, ignore the rest
                var $svg = jQuery(data).find('svg');
        
                // Add replaced image's ID to the new SVG
                if(typeof imgID !== 'undefined') {
                    $svg = $svg.attr('id', imgID);
                }
                // Add replaced image's classes to the new SVG
                if(typeof imgClass !== 'undefined') {
                    $svg = $svg.attr('class', imgClass+' replaced-svg');
                }
        
                // Remove any invalid XML tags as per http://validator.w3.org
                $svg = $svg.removeAttr('xmlns:a');
                
                // Check if the viewport is set, else we gonna set it if we can.
                if(!$svg.attr('viewBox') && $svg.attr('height') && $svg.attr('width')) {
                    $svg.attr('viewBox', '0 0 ' + $svg.attr('height') + ' ' + $svg.attr('width'));
                }
        
                // Replace image with new SVG
                $img.replaceWith($svg);
        
            }, 'xml');
        });
    });


    /* 14: Preloader
    ==============================================*/

    $(window).on('load', function(){

        function removePreloader() {
            var preLoader = $('.preLoader');
            preLoader.fadeOut();
        }
        setTimeout(removePreloader, 250);
    });


    /* 15: Content animation
    ==============================================*/

    $(window).on('load', function(){

        var $animateEl = $('[data-animate]');

        $animateEl.each(function () {
            var $el = $(this),
                $name = $el.data('animate'),
                $duration = $el.data('duration'),
                $delay = $el.data('delay');

            $duration = typeof $duration === 'undefined' ? '0.6' : $duration ;
            $delay = typeof $delay === 'undefined' ? '0' : $delay ;

            $el.waypoint(function () {
                $el.addClass('animated ' + $name)
                   .css({
                        'animation-duration': $duration + 's',
                        'animation-delay': $delay + 's'
                   });
            }, {offset: '93%'});
        });
    });
    

    /* 16: Background image
    ==============================================*/

    var bgImg = $('[data-bg-img]');

    bgImg.css('background-image', function(){
        return 'url(' + $(this).data('bg-img') + ')';
    });

    /* 17: Mega Menu
    ==============================================*/
    if ($(window).width() <= 991) {
        $(".mega-menu").prependTo('.mega-drop-down > ul > li');
    };


    /* 18: Matrix Effect
    ==============================================*/
    var c = document.getElementById("c");
    if( c ){
        var ctx = c.getContext("2d");

        //making the canvas full screen

        c.height = window.innerHeight;
        c.width = window.innerWidth;

        //chinese characters - taken from the unicode charset
        var chinese = "01";
        //converting the string into an array of single characters
        chinese = chinese.split("");

        var font_size = 10;
        var columns = c.width / font_size; //number of columns for the rain
        //an array of drops - one per column
        var drops = [];
        //x below is the x coordinate
        //1 = y co-ordinate of the drop(same for every drop initially)
        for (var x = 0; x < columns; x++)
            drops[x] = 1;

        //drawing the characters
        function draw() {
            //Black BG for the canvas
            //translucent BG to show trail
            ctx.fillStyle = "rgba(23,100,227, .2)";
            ctx.fillRect(0, 0, c.width, c.height);

            ctx.fillStyle = "rgba(255,255,255,.3)"; //green text
            ctx.font = font_size + "px arial";
            //looping over drops
            for (var i = 0; i < drops.length; i++) {
                //a random chinese character to print
                var text = chinese[Math.floor(Math.random() * chinese.length)];
                //x = i*font_size, y = value of drops[i]*font_size
                ctx.fillText(text, i * font_size, drops[i] * font_size);

                //sending the drop back to the top randomly after it has crossed the screen
                //adding a randomness to the reset to make the drops scattered on the Y axis
                if (drops[i] * font_size > c.height && Math.random() > 0.975)
                    drops[i] = 0;

                //incrementing Y coordinate
                drops[i]++;
            }
        }

        setInterval(draw, 33);
    }

    /*==================================
    19: Ajax Contact Form 
    ====================================*/

    $('.footer-form form, .contact-form form').on('submit', function(e) {
        e.preventDefault();

        var $el = $(this);

        $.post($el.attr('action'), $el.serialize(), function(res){
            var response = JSON.parse( res );
            $el.parent('.footer-form, .contact-form').find('.form-response').html('<span>' + response[1] + '</span>');
        });
    });

})(jQuery);