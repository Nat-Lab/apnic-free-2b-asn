apnic-free-2b-asn
---

`apnic-free-2b-asn` is a very simple python script that lists all available (unassigned) 2-byte ASNs in the APNIC region. It first fetches all ASNs delegated to APNIC [here](https://raw.githubusercontent.com/rfc1036/whois/next/as_del_list"), then gets all assigned ASNs [here](https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz), and finishing up by excluding all NIR `as-block`s with the data available [here](https://ftp.apnic.net/apnic/whois/apnic.db.as-block.gz).

### Why?

We use this to demonstrate the scarcity of 2-byte ASN. As the time of writing (Jul-2-2020), APNIC has only 535 2-byte ASNs left.

```
% python3 ./free2b.py
535 free 2-byte ASNs found:
  9434  9516  9748 10153 17441 17652 17729 17830 18054 18174 18250 18253 18404
 23865 23889 23914 24026 24062 24105 24381 24397 24453 38023 38038 38041 38042
 38047 38063 38070 38073 38074 38136 38137 38173 38175 38179 38194 38206 38208
 38215 38221 38222 38230 38237 38240 38254 38255 38272 38281 38282 38308 38323
 38324 38439 38440 38446 38449 38453 38459 38464 38530 38535 38537 38540 38542
 38548 38552 38558 38563 38576 38579 38588 38602 38604 38607 38613 38619 38620
 38657 38717 38721 38723 38745 38747 38821 38824 38828 38878 38879 38890 38893
 38897 38898 38904 38907 38908 45122 45123 45124 45129 45130 45132 45137 45141
 45149 45151 45169 45174 45180 45181 45183 45185 45196 45203 45216 45225 45231
 45233 45236 45238 45242 45253 45257 45258 45260 45262 45266 45281 45283 45329
 45332 45336 45339 45358 45416 45421 45423 45435 45438 45439 45440 45443 45451
 45464 45465 45468 45478 45482 45488 45492 45497 45507 45515 45516 45521 45523
 45524 45529 45564 45565 45568 45569 45571 45579 45598 45602 45606 45617 45618
 45619 45628 45632 45639 45643 45645 45646 45647 45659 45695 45739 45740 45743
 45745 45751 45756 45771 45774 45777 45778 45784 45790 45812 45818 45831 45835
 45862 45866 45869 45877 45880 45882 45883 45886 45889 45890 45907 45914 45923
 45928 45933 45948 45952 45957 46072 46074 46076 46077 55297 55299 55327 55335
 55338 55345 55346 55362 55364 55367 55370 55371 55401 55404 55432 55438 55442
 55445 55447 55450 55452 55458 55473 55475 55481 55484 55495 55499 55503 55513
 55528 55530 55537 55544 55548 55556 55560 55565 55568 55572 55640 55643 55645
 55647 55648 55708 55718 55727 55728 55735 55737 55738 55744 55749 55751 55753
 55758 55763 55768 55777 55783 55787 55788 55791 55800 55801 55809 55810 55812
 55823 55827 55830 55835 55838 55841 55842 55869 55875 55881 55882 55917 55930
 55935 55939 55942 55945 55950 55955 56016 56021 56022 56029 56049 56063 56066
 56069 56070 56071 56075 56078 56083 56090 56091 56096 56139 56162 56165 56168
 56170 56181 56185 56188 56191 56213 56217 56226 56267 56269 56275 56288 56297
 56299 56303 56310 56313 56319 58368 58407 58450 58455 58458 58472 58508 58531
 58575 58592 58595 58596 58603 58607 58632 58636 58638 58639 58660 58661 58662
 58667 58673 58674 58680 58694 58705 58711 58724 58727 58728 58733 58743 58745
 58753 58754 58783 58798 58799 58801 58802 58804 58870 58871 58873 58887 58896
 58917 58919 58934 58937 58939 58948 58956 58960 58973 58977 58978 59208 59213
 59220 59240 59244 59247 59255 59260 59264 59266 59295 59320 59328 59344 59351
 59354 59372 59373 59377 59380 63831 63845 63853 63856 63924 63936 63937 63947
 63952 63958 63960 63973 63976 63985 63990 63994 63995 64001 64007 64011 64017
 64035 64036 64038 64040 64042 64048 64051 64068 64083 64084 64085 64091 64094
 64097 64317 64318 64319 64320 64321 64322 64323 64324 64325 64326 64327 64328
 64329 64330 64331 64332 64333 64334 64335 64336 64337 64338 64339 64340 64341
 64342 64343 64344 64345 64346 64347 64348 64349 64350 64351 64352 64353 64354
 64355 64356 64357 64358 64359 64360 64361 64362 64363 64364 64365 64366 64367
 64368 64369 64370 64371 64372 64373 64374 64375 64376 64377 64378 64379 64380
 64381 64382 64383 64384 64385 64386 64387 64388 64389 64390 64391 64392 64393
 64394 64395
% date
Thu Jul  2 06:12:34 EDT 2020
 ```

### License

UNLICENSE