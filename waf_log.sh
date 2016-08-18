#!/bin/bash

#防火墙日志所在目录
log_path=/usr/local/nginx/logs/hack/
log_ext=*.log

if [  $1 ] ;then

	#是否需要取前几条
	if [ ${2:0:3}=='top' ] ;then
		is_top=true
	else
		is_top=false
	fi
	
	#排序后要取的条数
	item_num=${2:4:5}
	if [ ! $item_num ]; then  
	       $item_num=10 
	fi  
fi

#按照IP分组统计，排序
ip_count_sort (){
	if [ is_top ];then
		awk -F'#' '{ip[$(1)]+=1}; END {for(i in ip) print i, ip[i]}' ${log_path}${log_ext}| sort -k 2 -nr | head -${item_num}
	else
		awk -F'#' '{ip[$(1)]+=1}; END {for(i in ip) print i, ip[i]}' ${log_path}${log_ext}| sort -k 2 -nr
	
	fi
	 
}

#按照URL分组统计，排序
url_count_sort (){
	if [ is_top ];then
		awk -F'#' '{url[$(4)]+=1}; END {for(i in url) print i, url[i]}' ${log_path}${log_ext}| sort -nr | head -${item_num}
	else
		awk -F'#' '{url[$(4)]+=1}; END {for(i in url) print i, url[i]}' ${log_path}${log_ext}| sort -nr 
	
	fi
}

#按照时间排序输出IP和攻击地址
time_count_sort (){
	awk -F'#' '{date[$(2)]+=1}; END {for(i in date) print i, date[i]}' ${log_path}${log_ext}|sort -k 2 -nr 
}

case $1 in
  ip_count_sort )
        ip_count_sort
        ;;
  url_count_sort )
        url_count_sort
        ;;
  time_count_sort )
        time_count_sort
        ;;
  * )
    echo "Use:  ip_count_sort top_num|url_count_sort top_num|time_count_sort"
        ;;
esac