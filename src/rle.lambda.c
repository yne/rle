size_t make_sdu_nb=0;
rle_sdu_t curr_sdu = {size:62,data:"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"};
rle_sdu_t*make_sdu(){
	memset(&curr_sdu._,0,sizeof(curr_sdu._));
	return (make_sdu_nb++<MAX_GENERATED_SDU)?&curr_sdu:NULL;
}

rle_fpdu_t saved_fpdu[MAX_GENERATED_SDU*10]={};
size_t saved_fpdu_nb = 0;
rle_fpdu_t*save_fpdu(){
	return (saved_fpdu_nb<MAX_GENERATED_SDU*10-1)?&saved_fpdu[saved_fpdu_nb++]:NULL;
}
size_t loaded_fpdu_nb = 0;
rle_fpdu_t*load_fpdu(){
	return (loaded_fpdu_nb<MAX_GENERATED_SDU*10)?&saved_fpdu[loaded_fpdu_nb++]:NULL;
}
rle_sdu_t diffed_sdu = {size:0};
rle_sdu_t*diff_sdu(){
	if(diffed_sdu.size){//not first call
		/* check the previously outputed SDU before sending another one */
		DUMP(&diffed_sdu,sizeof(diffed_sdu))
	}
	memset(&diffed_sdu._,0,sizeof(diffed_sdu._));
	return &diffed_sdu;
}