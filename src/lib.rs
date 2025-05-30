use binaryninja::{
    binary_view::BinaryViewExt as _,
    logger::Logger,
    low_level_il::{
        function::{LowLevelILFunction, Mutable, NonSSA},
        instruction::{LowLevelILInstruction, LowLevelInstructionIndex},
        lifting::LowLevelILLabel,
    },
    rc::Ref,
    workflow::{Activity, AnalysisContext, Workflow},
};
use bn_bdash_extras::{activity, llil::match_instr};

const ARM64E_PAC_ACTIVITY_NAME: &str = "bdash.arm64e-pac";

fn tag_type_for_view(
    view: &binaryninja::binary_view::BinaryView,
) -> Ref<binaryninja::tags::TagType> {
    view.tag_type_by_name("arm64e PAC")
        .unwrap_or_else(|| view.create_tag_type("arm64e PAC", "PAC"))
}

fn process_instruction<'func>(
    llil: &'func LowLevelILFunction<Mutable, NonSSA>,
    instr: &'func LowLevelILInstruction<'func, Mutable, NonSSA>,
) -> Option<u64> {
    // Match `<dest> = <reg_b> ^ (<reg_b> << 1)`
    let dest = match_instr! {
        instr,
        SetReg(dest, Xor(Reg(left_reg), Lsl(Reg(shifted_reg), Const(1))))
            if left_reg == shifted_reg => *dest,
        _ => return None,
    };

    // Followed by `if ((<reg> & 0x40000000) == 0)`
    let next = llil.instruction_from_index(instr.index.next())?;
    let true_target = match_instr! {
        next,
        If(CmpE(And(Reg(reg), Const(0x4000_0000)), Const(0)), true_target, _)
            if dest == reg => *true_target,
        _ => return None,
    };

    log::debug!(
        "Disabling explicit PAC check at {:#0x}-{:#0x}",
        instr.address(),
        next.address()
    );

    if true_target.index == instr.index.next() {
        // Branch target is next instruction so we can replace the `if` with a `nop`.
        unsafe {
            llil.set_current_address(next.address());
            llil.replace_expression(next.expr_idx(), llil.nop());
        };
    } else {
        // Target is further afield so we replace the `if` with a `goto`.
        let mut label = LowLevelILLabel::new();
        label.operand = true_target.index.0;
        unsafe {
            llil.set_current_address(next.address());
            llil.replace_expression(next.expr_idx(), llil.goto(&mut label));
        };
    }

    // `xor` is always replaced with a `nop`.
    unsafe {
        llil.set_current_address(instr.address());
        llil.replace_expression(instr.expr_idx(), llil.nop());
    }

    Some(next.address())
}

fn process_arm64e_pac(analysis_context: &AnalysisContext) {
    let Some(llil) = (unsafe { analysis_context.llil_function() }) else {
        return;
    };

    let mut did_update = false;
    for idx in 0..llil.instruction_count() {
        let Some(instr) = llil.instruction_from_index(LowLevelInstructionIndex(idx)) else {
            continue;
        };

        let Some(address) = process_instruction(&llil, &instr) else {
            continue;
        };

        did_update = true;

        analysis_context.function().add_tag(
            &tag_type_for_view(&analysis_context.view()),
            "Eliminated explicit pointer authentication check",
            Some(address),
            false,
            None,
        );
    }

    if did_update {
        llil.generate_ssa_form();
    }
}

fn register_activity(workflow: &Workflow) {
    if !workflow.registered() {
        log::debug!(
            "Skipping activity registration for workflow {} as it is not registered",
            workflow.name()
        );
        return;
    }

    let workflow = workflow.clone_to(&workflow.name());
    let config = activity::Config::action(
        ARM64E_PAC_ACTIVITY_NAME,
        "Remove explicit arm64e PAC checks",
        "Remove the explicit arm64e pointer authentication checks the compiler emits prior to tail calls",
    );
    let activity = Activity::new_with_action(&config.to_string(), process_arm64e_pac);
    workflow.register_activity(&activity).unwrap();
    workflow.insert(
        "core.function.generateMediumLevelIL",
        [ARM64E_PAC_ACTIVITY_NAME],
    );
    workflow.register().unwrap();
}

#[unsafe(no_mangle)]
pub extern "C" fn CorePluginDependencies() {
    use binaryninja::add_optional_plugin_dependency;
    add_optional_plugin_dependency("workflow_objc");
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("arm64 PAC")
        .with_level(log::LevelFilter::Debug)
        .init();

    register_activity(&Workflow::instance("core.function.metaAnalysis"));
    register_activity(&Workflow::instance("core.function.objectiveC"));

    true
}
